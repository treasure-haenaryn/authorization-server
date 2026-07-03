package com.haenaryn.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * OAuth2/OIDC 프로토콜 엔드포인트(인가서버)와 일반 웹 요청(로그인 폼 등)을 별도
 * {@link SecurityFilterChain}으로 분리한다.
 *
 * <p>{@code HttpSecurity.oauth2AuthorizationServer(...)} DSL을 사용한다 — Spring Security
 * 7(Spring Boot 4) 공식 Getting Started 가이드가 권장하는 최신 패턴. 예전에는
 * {@code OAuth2AuthorizationServerConfigurer.authorizationServer()}를 직접 인스턴스화해서
 * {@code http.with(configurer, ...)}로 붙였는데, 이 방식은 그 설정 객체 타입을 직접 import할
 * 필요가 없어 더 간결하다 (람다 파라미터로만 쓰이므로 타입 추론됨).</p>
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
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
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Authorization Code Flow 진입 시 사용자에게 보여줄 로그인 폼.
                // UserDetailsServiceImpl + PasswordEncoderConfig가 여기서 쓰인다.
                .formLogin(Customizer.withDefaults())
                .logout((logout) -> logout
                        .logoutUrl("/auth/logout")
                        .logoutSuccessUrl("/")
                );

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
