package com.haenaryn.authserver.security;

import com.haenaryn.authserver.cache.RedisKeys;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * {@code /userinfo}에서 블랙리스트(로그아웃) 등록된 Access Token을 거부하는 필터 검증.
 * Redis 장애/서킷 OPEN 시에는 fail-open으로 통과시켜야 한다.
 */
@ExtendWith(MockitoExtension.class)
class AccessTokenBlacklistFilterTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;
    @Mock
    private FilterChain filterChain;

    private CircuitBreaker circuitBreaker;
    private AccessTokenBlacklistFilter filter;

    @BeforeEach
    void setUp() {
        circuitBreaker = CircuitBreaker.ofDefaults("test");
        filter = new AccessTokenBlacklistFilter(redisTemplate, circuitBreaker);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private Jwt jwtWithJti(String jti) {
        return Jwt.withTokenValue("token-value")
                .header("alg", "ES256")
                .claim("jti", jti)
                .subject("lee@haenaryn.com")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(1800))
                .build();
    }

    @Test
    void passes_through_when_authentication_is_not_a_jwt() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void passes_through_when_jti_is_not_blacklisted() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtWithJti("jti-ok")));
        when(redisTemplate.hasKey(RedisKeys.blacklist("jti-ok"))).thenReturn(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void rejects_request_when_jti_is_blacklisted() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtWithJti("jti-blacklisted")));
        when(redisTemplate.hasKey(RedisKeys.blacklist("jti-blacklisted"))).thenReturn(true);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getContentAsString()).contains("TOKEN_BLACKLISTED");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void fails_open_when_redis_throws() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtWithJti("jti-any")));
        when(redisTemplate.hasKey(RedisKeys.blacklist("jti-any"))).thenThrow(new RuntimeException("Redis connection refused"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void fails_open_when_circuit_breaker_is_open_without_even_calling_redis() throws Exception {
        // Redis가 "느려지기만" 해서 서킷이 OPEN된 상황을 재현한다 — 이때는 Redis를 아예
        // 호출하지 않고(타임아웃을 기다리지 않고) 바로 fail-open으로 통과해야 한다.
        circuitBreaker.transitionToOpenState();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwtWithJti("jti-any")));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }
}
