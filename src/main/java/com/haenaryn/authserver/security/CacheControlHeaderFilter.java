package com.haenaryn.authserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWKS/OIDC 디스커버리 응답에만 {@code Cache-Control}을 실어 CDN/리버스 프록시가
 * 캐싱할 수 있게 한다.
 */
public class CacheControlHeaderFilter extends OncePerRequestFilter {

    private static final String CACHE_CONTROL_VALUE = "public, max-age=300"; // 5분

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (isCacheable(path)) {
            response.setHeader("Cache-Control", CACHE_CONTROL_VALUE);
        }
        filterChain.doFilter(request, response);
    }

    private boolean isCacheable(String path) {
        return path.equals("/oauth2/jwks") || path.startsWith("/.well-known/");
    }
}
