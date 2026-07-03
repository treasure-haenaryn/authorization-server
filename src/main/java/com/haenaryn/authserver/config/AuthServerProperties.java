package com.haenaryn.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth-server")
public record AuthServerProperties(
        String issuer,
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
     *
     * <p>{@code encryptionKey}는 {@code source=DATABASE}일 때만 사용하는 AES-256 키
     * (Base64, 32바이트). {@code jwk_keys.encrypted_private_key}를 복호화하는 데 쓴다.</p>
     */
    public record SigningKey(
            SigningKeySourceType source,
            String encryptionKey
    ) {
    }

    public enum SigningKeySourceType {
        IN_MEMORY,
        DATABASE
    }
}
