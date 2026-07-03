package com.haenaryn.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth-server")
public record AuthServerProperties(
        Token token,
        Security security,
        SigningKey signingKey
) {
    public record Token(
            long accessTokenTtlMinutes,
            long idTokenTtlMinutes,
            long refreshTokenTtlDays
    ) {
    }

    public record Security(
            int loginFailLockThreshold,
            long loginFailWindowHours
    ) {
    }

    /**
     * 서명 알고리즘은 ES256(EC P-256) 고정. API Gateway의 JwtFilter가 ECDSAVerifier
     * 기준으로 구현되어 있어 알고리즘을 통일.
     */
    public record SigningKey(
            SigningKeySourceType source
    ) {
    }

    public enum SigningKeySourceType {
        IN_MEMORY,
        DATABASE
    }
}
