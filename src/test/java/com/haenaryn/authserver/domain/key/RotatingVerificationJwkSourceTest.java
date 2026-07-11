package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.config.EcKeyGenerator;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RotatingVerificationJwkSourceTest {

    private static final AuthServerProperties.SigningKey SIGNING_KEY = new AuthServerProperties.SigningKey(
            AuthServerProperties.SigningKeySourceType.DATABASE, "unused", 90, 60, 30);
    private static final JWKSelector SELECT_ALL = new JWKSelector(new JWKMatcher.Builder().build());

    @Mock
    private JwkKeyRepository jwkKeyRepository;

    private RotatingVerificationJwkSource source;

    @BeforeEach
    void setUp() {
        AuthServerProperties properties = new AuthServerProperties(null, null, null, SIGNING_KEY, null);
        source = new RotatingVerificationJwkSource(jwkKeyRepository, properties);
    }

    @Test
    void get_exposes_active_and_retiring_keys_as_public_jwks() {
        ECKey activeKey = EcKeyGenerator.generate();
        ECKey retiringKey = EcKeyGenerator.generate();
        JwkKeyEntity activeEntity = entityOf(activeKey);
        JwkKeyEntity retiringEntity = entityOf(retiringKey);

        when(jwkKeyRepository.findAllByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.RETIRING)))
                .thenReturn(List.of(activeEntity, retiringEntity));

        List<JWK> result = source.get(SELECT_ALL, null);

        assertThat(result).hasSize(2);
        assertThat(result).extracting(JWK::getKeyID)
                .containsExactlyInAnyOrder(activeKey.getKeyID(), retiringKey.getKeyID());
        assertThat(result).allMatch(jwk -> !jwk.isPrivate());
    }

    @Test
    void get_caches_result_within_ttl_and_does_not_hit_repository_again() {
        when(jwkKeyRepository.findAllByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.RETIRING)))
                .thenReturn(List.of());

        source.get(SELECT_ALL, null);
        source.get(SELECT_ALL, null);

        verify(jwkKeyRepository, times(1)).findAllByStatusIn(List.of(KeyStatus.ACTIVE, KeyStatus.RETIRING));
    }

    private JwkKeyEntity entityOf(ECKey key) {
        return JwkKeyEntity.builder()
                .keyId(key.getKeyID())
                .curve(key.getCurve().getName())
                .algorithm(key.getAlgorithm().getName())
                .encryptedPrivateKey("not-used-in-this-test")
                .publicKey(key.toPublicJWK().toJSONString())
                .build();
    }
}
