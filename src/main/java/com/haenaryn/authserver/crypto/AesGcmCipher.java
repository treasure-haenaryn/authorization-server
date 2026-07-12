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
 * 출력 포맷은 {@code Base64(IV(12바이트) + 암호문+인증태그)}.
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
