package com.haenaryn.authserver.config;

import com.haenaryn.authserver.security.AccessTokenBlacklistFilter;
import com.haenaryn.authserver.security.LoginFailureHandler;
import com.haenaryn.authserver.security.LoginSuccessHandler;
import com.haenaryn.authserver.security.RateLimitFilter;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * OAuth2/OIDC 프로토콜 엔드포인트(인가서버)와 일반 웹 요청(로그인 폼 등)을 별도
 * {@link SecurityFilterChain}으로 분리한다.
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                        AuthServerProperties properties,
                                                                        RedisTemplate<String, String> redisTemplate,
                                                                        LettuceBasedProxyManager<String> rateLimitProxyManager) throws Exception {
        http
                .oauth2AuthorizationServer((authorizationServer) -> {
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                    // OIDC 1.0 확장 활성화 — /userinfo, /.well-known/openid-configuration 자동 노출
                    authorizationServer.oidc(Customizer.withDefaults());
                })
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                // 브라우저(HTML) 요청이 인증 없이 /oauth2/authorize 등에 오면 /login으로 리다이렉트.
                // API 클라이언트(JSON) 요청은 이 EntryPoint 대상이 아니라 기본 401 처리로 빠진다.
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // /userinfo가 Bearer Access Token으로 인증되도록 리소스 서버 기능을 켠다.
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
                .headers((headers) -> headers.httpStrictTransportSecurity((hsts) -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                ))
                // BearerTokenAuthenticationFilter 뒤에 둬야 SecurityContext에 JwtAuthenticationToken이
                // 채워진 상태에서 jti 클레임을 검사할 수 있다.
                .addFilterAfter(
                        new AccessTokenBlacklistFilter(redisTemplate),
                        BearerTokenAuthenticationFilter.class
                )
                // /oauth2/token은 클라이언트 인증(OAuth2ClientAuthenticationFilter)보다도 먼저
                // 걸러야 브루트포스/자격증명 스터핑 시도가 인증 로직까지 도달하지 않는다.
                .addFilterBefore(
                        new RateLimitFilter(rateLimitProxyManager,
                                properties.rateLimit().capacity(), properties.rateLimit().refillTokensPerMinute()),
                        UsernamePasswordAuthenticationFilter.class
                );

        if (properties.security().requireHttps()) {
            http.redirectToHttps(Customizer.withDefaults());
        }

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                            LoginSuccessHandler loginSuccessHandler,
                                                            LoginFailureHandler loginFailureHandler,
                                                            AuthServerProperties properties,
                                                            LettuceBasedProxyManager<String> rateLimitProxyManager) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // /auth/logout은 세션/폼 인증이 아니라 컨트롤러 내부에서 Bearer
                        // access_token 자체를 검증하므로, 시큐리티 필터 단계에서는 permitAll.
                        .requestMatchers(HttpMethod.POST, "/auth/logout").permitAll()
                        .anyRequest().authenticated()
                )
                // Authorization Code Flow 진입 시 사용자에게 보여줄 로그인 폼.
                // UserDetailsServiceImpl + PasswordEncoderConfig가 여기서 쓰인다.
                .formLogin((form) -> form
                        .successHandler(loginSuccessHandler)
                        .failureHandler(loginFailureHandler)
                )
                // /auth/logout은 Bearer 토큰으로 인증하는 API 클라이언트(모바일 앱, SPA 등)가
                // 호출하는 엔드포인트라 세션 쿠키 기반 CSRF 토큰이 없다 — CSRF 검사 대상에서 제외.
                .csrf((csrf) -> csrf.ignoringRequestMatchers("/auth/logout"))
                .headers((headers) -> headers.httpStrictTransportSecurity((hsts) -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                ))
                // /login(폼 로그인 POST)에 대한 Rate Limiting. UsernamePasswordAuthenticationFilter가
                // 실제 인증(비밀번호 검증)을 수행하는 필터라, 그 앞에서 걸러야 브루트포스 시도가
                // 계정 잠금 로직(LoginFailureHandler)까지 가기 전에 이미 차단된다.
                .addFilterBefore(
                        new RateLimitFilter(rateLimitProxyManager,
                                properties.rateLimit().capacity(), properties.rateLimit().refillTokensPerMinute()),
                        UsernamePasswordAuthenticationFilter.class
                );

        if (properties.security().requireHttps()) {
            http.redirectToHttps(Customizer.withDefaults());
        }

        return http.build();
    }

    /**
     * 발급되는 모든 토큰(Access/ID Token)의 {@code iss} 클레임과 JWKS/디스커버리 엔드포인트의
     * 기준 URL이 된다. 게이트웨이/클라이언트가 이 값으로 discovery 문서를 찾아간다.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AuthServerProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.issuer())
                .build();
    }
}
