package com.haenaryn.authserver.domain.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Refresh Token용 오페이크 토큰 생성 + SHA-256 해싱 유틸리티.
 */
public final class TokenHasher {

    private static final int TOKEN_BYTE_LENGTH = 32; // 256bit

    private TokenHasher() {
    }

    /** 클라이언트에게 내려줄 원문 refresh token (Base64 URL-safe, 패딩 없음). */
    public static String generateOpaqueToken() {
        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /** DB에는 이 해시값만 저장한다 (원문 미저장). */
    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다.", e);
        }
    }
}
