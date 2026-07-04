package com.haenaryn.authserver.config;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

/**
 * EC(P-256) 키페어 생성 유틸리티. 서명 알고리즘은 ES256.
 */
public final class EcKeyGenerator {

    private static final Curve CURVE = Curve.P_256;

    private EcKeyGenerator() {
    }

    /**
     * 새 EC(P-256) 키페어를 생성하고 Nimbus {@link ECKey}(JWK) 형태로 반환한다.
     * keyID는 랜덤 UUID — JWKS에서 kid로 노출되어 클라이언트/게이트웨이가 키를 식별하는 데 사용된다.
     */
    public static ECKey generate() {
        KeyPair keyPair = generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        return new ECKey.Builder(CURVE, publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .algorithm(new Algorithm("ES256"))
                .build();
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(CURVE.getStdName()));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("EC 키페어 생성 실패", e);
        }
    }
}
