package com.haenaryn.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Access Token / ID Token의 JWS 헤더 알고리즘을 ES256으로 명시적으로 고정한다.
 *
 * <p>{@link EcKeyGenerator}에서 JWK 자체에 {@code alg: ES256}을 이미 지정해뒀지만,
 * 여기서도 한 번 더 강제하는 이유는 방어 심층화(defense in depth) 때문이다 — JWKS
 * 소스가 향후 바뀌거나(예: prod DB 소스에서 alg 필드가 비어있는 레거시 데이터가
 * 섞이는 경우) 프레임워크가 다른 알고리즘을 추론해 서명하는 사고를 원천 차단한다.
 * "alg 필드가 클라이언트/저장소에 따라 흔들려도 이 서버는 무조건 ES256만 서명한다"는
 * 불변 조건을 코드로 못 박아두는 것.</p>
 */
@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
    }
}
