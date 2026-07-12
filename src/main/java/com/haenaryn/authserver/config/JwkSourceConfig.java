package com.haenaryn.authserver.config;

import com.haenaryn.authserver.domain.key.ActiveSigningJwkSource;
import com.haenaryn.authserver.domain.key.RotatingVerificationJwkSource;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

/**
 * Authorization Server가 토큰 서명(JWS)과 {@code /oauth2/jwks} 노출에 사용할
 * EC(P-256) 키 소스를 구성한다. 서명 알고리즘은 ES256.
 */
@Configuration
@EnableConfigurationProperties(AuthServerProperties.class)
public class JwkSourceConfig {

    private final AuthServerProperties properties;

    public JwkSourceConfig(AuthServerProperties properties) {
        this.properties = properties;
    }

    /** JWKS 엔드포인트 노출 + {@code JwtDecoder}(userinfo 검증)에 쓰이는 검증용 소스. */
    @Bean
    @Primary
    public JWKSource<SecurityContext> jwkSource(RotatingVerificationJwkSource rotatingVerificationJwkSource) {
        return switch (properties.signingKey().source()) {
            case IN_MEMORY -> new ImmutableJWKSet<>(new JWKSet(EcKeyGenerator.generate()));
            case DATABASE -> rotatingVerificationJwkSource;
        };
    }

    /** {@code source=database}에서만 서명 전용 {@link ActiveSigningJwkSource}로 인코더를 등록한다. */
    @Bean
    @ConditionalOnProperty(prefix = "auth-server.signing-key", name = "source", havingValue = "database")
    public JwtEncoder jwtEncoder(ActiveSigningJwkSource activeSigningJwkSource) {
        return new NimbusJwtEncoder(activeSigningJwkSource);
    }

    /** {@code /userinfo} 검증용 {@link JwtDecoder}. 리소스 서버 기능이 필요해 별도 등록한다. */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
