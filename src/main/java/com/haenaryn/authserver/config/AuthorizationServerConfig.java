package com.haenaryn.authserver.config;

import com.haenaryn.authserver.security.AccessTokenBlacklistFilter;
import com.haenaryn.authserver.security.CacheControlHeaderFilter;
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
import org.springframework.security.web.header.HeaderWriterFilter;
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
                // .oidc()를 getEndpointsMatcher()보다 먼저 호출해야 OIDC 엔드포인트가 매처에 포함된다.
                .oauth2AuthorizationServer((authorizationServer) -> {
                    authorizationServer.oidc(Customizer.withDefaults());
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                })
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/.well-known/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
                .headers((headers) -> headers.httpStrictTransportSecurity((hsts) -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                ))
                .addFilterAfter(
                        new AccessTokenBlacklistFilter(redisTemplate),
                        BearerTokenAuthenticationFilter.class
                )
                .addFilterBefore(
                        new RateLimitFilter(rateLimitProxyManager,
                                properties.rateLimit().capacity(), properties.rateLimit().refillTokensPerMinute()),
                        UsernamePasswordAuthenticationFilter.class
                )
                .addFilterAfter(new CacheControlHeaderFilter(), HeaderWriterFilter.class);

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
                        .requestMatchers(HttpMethod.POST, "/auth/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin((form) -> form
                        .successHandler(loginSuccessHandler)
                        .failureHandler(loginFailureHandler)
                )
                .csrf((csrf) -> csrf.ignoringRequestMatchers("/auth/logout"))
                .headers((headers) -> headers.httpStrictTransportSecurity((hsts) -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                ))
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
