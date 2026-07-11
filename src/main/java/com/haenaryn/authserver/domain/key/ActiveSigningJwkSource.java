package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.crypto.AesGcmCipher;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;

/** {@code JwtEncoder}(토큰 서명 전용) 키 소스. 항상 정확히 하나의 키(ACTIVE)만 반환한다. */
@Component
public class ActiveSigningJwkSource implements JWKSource<SecurityContext> {

    private final JwkKeyRepository jwkKeyRepository;
    private final AuthServerProperties properties;
    private final TtlCache<JWKSet> cache;

    public ActiveSigningJwkSource(JwkKeyRepository jwkKeyRepository, AuthServerProperties properties) {
        this.jwkKeyRepository = jwkKeyRepository;
        this.properties = properties;
        this.cache = new TtlCache<>(
                Duration.ofSeconds(properties.signingKey().cacheTtlSeconds()),
                this::loadSigningKey
        );
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        return jwkSelector.select(cache.get());
    }

    private JWKSet loadSigningKey() {
        JwkKeyEntity active = jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE)
                .orElseThrow(() -> new IllegalStateException(
                        "jwk_keys 테이블에 ACTIVE 서명키가 없습니다. "
                                + "KeyRotationService.rotate()로 최초 키를 생성해야 합니다 (JwkKeyBootstrap 참고)."));

        AesGcmCipher cipher = new AesGcmCipher(properties.signingKey().encryptionKey());
        String decryptedJwkJson = cipher.decrypt(active.getEncryptedPrivateKey());

        try {
            return new JWKSet(ECKey.parse(decryptedJwkJson));
        } catch (ParseException e) {
            throw new IllegalStateException(
                    "jwk_keys.id=" + active.getId() + " 의 복호화된 값이 올바른 EC JWK 형식이 아닙니다. "
                            + "암호화 키(ENCRYPTION_KEY)가 저장 시점과 다르거나 데이터가 손상됐을 수 있습니다.",
                    e
            );
        }
    }
}
