package com.haenaryn.authserver.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * jwk_keys.encrypted_private_key(운영환경 EC 개인키) 암복호화용 AES-256-GCM 유틸리티.
 *
 * <p>refresh token(SHA-256 해시, 되돌릴 필요 없음)과 달리, EC 개인키는 실제로
 * 복호화해서 서명 연산에 다시 써야 하므로 암호화(encryption)를 쓴다. GCM 모드를
 * 선택한 이유는 암호문 자체에 무결성 검증(인증 태그)이 포함돼 있어, 별도의 HMAC
 * 없이도 변조 탐지가 되기 때문이다 (CBC 모드는 이 기능이 없어 별도 MAC이 필요함).</p>
 *
 * <p>출력 포맷: {@code Base64(IV(12바이트) + 암호문+인증태그)}. IV를 암호문 앞에 붙여
 * 저장하는 이유는 복호화 시 같은 IV가 필요한데, IV 자체는 비밀값이 아니라 매번
 * 무작위로 새로 생성해 함께 저장해도 안전하기 때문이다 (재사용만 금지).</p>
 */
public final class AesGcmCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;

    private final SecretKeySpec secretKey;

    /**
     * @param base64Key Base64로 인코딩된 32바이트(256bit) AES 키
     */
    public AesGcmCipher(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalArgumentException(
                    "AES 암호화 키가 설정되지 않았습니다. auth-server.signing-key.encryption-key(ENCRYPTION_KEY 환경변수)를 확인하세요."
            );
        }
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        if (decoded.length != 32) {
            throw new IllegalArgumentException("AES-256 키는 32바이트여야 합니다. 현재 길이: " + decoded.length);
        }
        this.secretKey = new SecretKeySpec(decoded, "AES");
    }

    public String encrypt(String plainText) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] result = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

            return Base64.getEncoder().encodeToString(result);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM 암호화 실패", e);
        }
    }

    public String decrypt(String base64CipherText) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64CipherText);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            byte[] cipherText = new byte[decoded.length - IV_LENGTH_BYTES];
            System.arraycopy(decoded, 0, iv, 0, IV_LENGTH_BYTES);
            System.arraycopy(decoded, IV_LENGTH_BYTES, cipherText, 0, cipherText.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM 복호화 실패 (키 불일치 또는 데이터 변조 가능성)", e);
        }
    }
}
