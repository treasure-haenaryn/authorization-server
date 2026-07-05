package com.haenaryn.authserver.security;

import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.BucketProxy;
import io.github.bucket4j.distributed.proxy.RemoteBucketBuilder;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * bucket4j 토큰 버킷 기반 Rate Limiting 필터 검증.
 * 대상 경로 외에는 통과, 소진 시 429 + Retry-After, Redis 장애 시 fail-open을 확인한다.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RateLimitFilterTest {

    @Mock
    private LettuceBasedProxyManager<String> proxyManager;
    @Mock
    private RemoteBucketBuilder<String> bucketBuilder;
    @Mock
    private BucketProxy bucket;
    @Mock
    private ConsumptionProbe consumptionProbe;
    @Mock
    private FilterChain filterChain;

    private RateLimitFilter filter;

    @BeforeEach
    void setUp() {
        filter = new RateLimitFilter(proxyManager, 10, 10);
        when(proxyManager.builder()).thenReturn(bucketBuilder);
        when(bucketBuilder.build(any(String.class), any(Supplier.class))).thenReturn(bucket);
    }

    @Test
    void passes_through_paths_outside_the_limited_set() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/userinfo");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(proxyManager);
    }

    @Test
    void allows_request_and_sets_remaining_header_when_consumed() throws Exception {
        when(bucket.tryConsumeAndReturnRemaining(1)).thenReturn(consumptionProbe);
        when(consumptionProbe.isConsumed()).thenReturn(true);
        when(consumptionProbe.getRemainingTokens()).thenReturn(9L);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/oauth2/token");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(response.getHeader("X-RateLimit-Remaining")).isEqualTo("9");
        verify(bucketBuilder).build(eq("rate_limit:/oauth2/token:127.0.0.1"), any(Supplier.class));
    }

    @Test
    void rejects_request_with_429_and_retry_after_when_bucket_is_empty() throws Exception {
        when(bucket.tryConsumeAndReturnRemaining(1)).thenReturn(consumptionProbe);
        when(consumptionProbe.isConsumed()).thenReturn(false);
        when(consumptionProbe.getNanosToWaitForRefill()).thenReturn(5_000_000_000L);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("5");
        assertThat(response.getContentAsString()).contains("TOO_MANY_REQUESTS");
    }

    @Test
    void fails_open_when_proxy_manager_throws() throws Exception {
        when(bucketBuilder.build(any(String.class), any(Supplier.class))).thenThrow(new RuntimeException("Redis connection refused"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/oauth2/token");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }
}
