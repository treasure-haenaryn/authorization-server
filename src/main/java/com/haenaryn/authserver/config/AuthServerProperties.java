package com.haenaryn.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth-server")
public record AuthServerProperties(
        String issuer,
        Token token,
        Security security,
        SigningKey signingKey,
        RateLimit rateLimit
) {
    public record Token(
            long accessTokenTtlMinutes,
            long idTokenTtlMinutes,
            long refreshTokenTtlDays
    ) {
    }

    public record Security(
            int loginFailLockThreshold,
            long loginFailWindowHours,
            boolean requireHttps
    ) {
    }

    /**
     * Rate Limiting(bucket4j 토큰 버킷) 설정. {@code capacity}는 버킷 최대 용량(순간 버스트
     * 허용량), {@code refillTokensPerMinute}는 분당 리필되는 토큰 수(평균 처리율)다.
     */
    public record RateLimit(
            int capacity,
            int refillTokensPerMinute
    ) {
    }

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
