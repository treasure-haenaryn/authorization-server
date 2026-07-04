package com.haenaryn.authserver.security;

import com.haenaryn.authserver.exception.ErrorResponse;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

/**
 * {@code /oauth2/token}, {@code /login}에 대해 IP 기준 토큰 버킷 Rate Limiting을 적용한다.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private static final Set<String> LIMITED_PATHS = Set.of("/oauth2/token", "/login");

    private final LettuceBasedProxyManager<String> proxyManager;
    private final BucketConfiguration bucketConfiguration;

    public RateLimitFilter(LettuceBasedProxyManager<String> proxyManager,
                            int capacity,
                            int refillTokensPerMinute) {
        this.proxyManager = proxyManager;
        this.bucketConfiguration = BucketConfiguration.builder()
                .addLimit(limit -> limit.capacity(capacity).refillGreedy(refillTokensPerMinute, Duration.ofMinutes(1)))
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!LIMITED_PATHS.contains(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // forward-headers-strategy: native
        // 로드밸런서/리버스 프록시 뒤에서도 X-Forwarded-For 기준 실제 클라이언트 IP를 반환.
        String clientIp = request.getRemoteAddr();
        String key = "rate_limit:" + path + ":" + clientIp;

        try {
            Bucket bucket = proxyManager.builder().build(key, () -> bucketConfiguration);
            ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

            if (probe.isConsumed()) {
                response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
                filterChain.doFilter(request, response);
                return;
            }

            long retryAfterSeconds = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000L);
            writeTooManyRequests(response, retryAfterSeconds);
        } catch (Exception e) {
            // Fail-open
            log.warn("Redis 장애로 Rate Limiting 체크 실패, fail-open으로 통과: key={}", key, e);
            filterChain.doFilter(request, response);
        }
    }

    private void writeTooManyRequests(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "TOO_MANY_REQUESTS",
                "요청이 너무 많습니다. " + retryAfterSeconds + "초 후 다시 시도해주세요."
        );
        response.getWriter().write(toJson(body));
    }

    private String toJson(ErrorResponse body) {
        return "{"
                + "\"timestamp\":\"" + body.timestamp() + "\","
                + "\"status\":" + body.status() + ","
                + "\"code\":\"" + body.code() + "\","
                + "\"message\":\"" + escape(body.message()) + "\""
                + "}";
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
