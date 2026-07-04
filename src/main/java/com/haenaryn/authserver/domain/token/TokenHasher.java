package com.haenaryn.authserver.domain.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Refresh Token용 오페이크 토큰 생성 + SHA-256 해싱 유틸리티.
 *
 * <p>비밀번호와 달리 bcrypt 같은 느린 해시를 쓰지 않는 이유: 이 토큰은 서버가
 * {@link SecureRandom}으로 생성하는 고엔트로피(256bit) 무작위 값이라 이미 추측
 * 불가능하다. 빠른 SHA-256만으로도 역산 공격이 사실상 불가능하고, salt도 필요
 * 없다 (salt는 "같은 값 재사용" 방지 목적인데 애초에 유저마다 유니크한 무작위값이라
 * 그 위협 자체가 성립하지 않는다).</p>
 */
public final class TokenHasher {

    private static final int TOKEN_BYTE_LENGTH = 32; // 256bit

    private TokenHasher() {
    }

    /**
     * 클라이언트에게 내려줄 원문 refresh token. Base64 URL-safe(패딩 없음) 인코딩이라
     * 쿠키/헤더/쿼리스트링 어디에 넣어도 추가 이스케이프가 필요 없다.
     */
    public static String generateOpaqueToken() {
        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /** DB에는 이 해시값만 저장한다 (원문 미저장 — 보안 요구사항). */
    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256은 모든 JVM이 표준으로 지원하므로 정상 환경에서는 발생하지 않는다.
            throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다.", e);
        }
    }
}
