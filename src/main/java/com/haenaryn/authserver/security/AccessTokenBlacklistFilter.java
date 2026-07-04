package com.haenaryn.authserver.security;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.exception.ErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * {@code /userinfo}에서 로그아웃된(블랙리스트 등록된) Access Token을 거부한다.
 */
public class AccessTokenBlacklistFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenBlacklistFilter.class);

    private final RedisTemplate<String, String> redisTemplate;

    public AccessTokenBlacklistFilter(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            String jti = jwtAuthentication.getToken().getId();

            if (jti != null && isBlacklisted(jti)) {
                SecurityContextHolder.clearContext();
                writeUnauthorized(response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isBlacklisted(String jti) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(RedisKeys.blacklist(jti)));
        } catch (Exception e) {
            // Fail-open
            log.warn("Redis 장애로 블랙리스트 체크 실패, fail-open으로 통과: jti={}", jti, e);
            return false;
        }
    }

    private void writeUnauthorized(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ErrorResponse body = ErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                "TOKEN_BLACKLISTED",
                "로그아웃 처리된 토큰입니다."
        );
        response.getWriter().write(toJson(body));
    }

    private String toJson(ErrorResponse body) {
        return "{"
                + "\"timestamp\":\"" + body.timestamp() + "\","
                + "\"status\":" + body.status() + ","
                + "\"code\":\"" + body.code() + "\","
                + "\"message\":\"" + body.message() + "\""
                + "}";
    }
}
