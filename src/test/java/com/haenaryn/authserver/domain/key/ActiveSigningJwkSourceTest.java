package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.config.EcKeyGenerator;
import com.haenaryn.authserver.crypto.AesGcmCipher;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ActiveSigningJwkSourceTest {

    private static final String ENCRYPTION_KEY = Base64.getEncoder().encodeToString(new byte[32]);
    private static final AuthServerProperties.SigningKey SIGNING_KEY = new AuthServerProperties.SigningKey(
            AuthServerProperties.SigningKeySourceType.DATABASE, ENCRYPTION_KEY, 90, 60, 30);
    private static final JWKSelector SELECT_ALL = new JWKSelector(new JWKMatcher.Builder().build());

    @Mock
    private JwkKeyRepository jwkKeyRepository;

    private ActiveSigningJwkSource source;

    @BeforeEach
    void setUp() {
        AuthServerProperties properties = new AuthServerProperties(null, null, null, SIGNING_KEY, null);
        source = new ActiveSigningJwkSource(jwkKeyRepository, properties);
    }

    @Test
    void get_returns_exactly_the_active_key_with_private_material() {
        ECKey activeKey = EcKeyGenerator.generate();
        AesGcmCipher cipher = new AesGcmCipher(ENCRYPTION_KEY);
        JwkKeyEntity activeEntity = JwkKeyEntity.builder()
                .keyId(activeKey.getKeyID())
                .curve(activeKey.getCurve().getName())
                .algorithm(activeKey.getAlgorithm().getName())
                .encryptedPrivateKey(cipher.encrypt(activeKey.toJSONString()))
                .publicKey(activeKey.toPublicJWK().toJSONString())
                .build();
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE))
                .thenReturn(Optional.of(activeEntity));

        List<JWK> result = source.get(SELECT_ALL, null);

        assertThat(result).hasSize(1);
        assertThat(result.getFirst().getKeyID()).isEqualTo(activeKey.getKeyID());
        assertThat(result.getFirst().isPrivate()).isTrue();
    }

    @Test
    void get_throws_when_no_active_key_exists() {
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> source.get(SELECT_ALL, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ACTIVE 서명키가 없습니다");
    }

    @Test
    void get_caches_result_within_ttl_and_does_not_hit_repository_again() {
        ECKey activeKey = EcKeyGenerator.generate();
        AesGcmCipher cipher = new AesGcmCipher(ENCRYPTION_KEY);
        JwkKeyEntity activeEntity = JwkKeyEntity.builder()
                .keyId(activeKey.getKeyID())
                .curve(activeKey.getCurve().getName())
                .algorithm(activeKey.getAlgorithm().getName())
                .encryptedPrivateKey(cipher.encrypt(activeKey.toJSONString()))
                .publicKey(activeKey.toPublicJWK().toJSONString())
                .build();
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE))
                .thenReturn(Optional.of(activeEntity));

        source.get(SELECT_ALL, null);
        source.get(SELECT_ALL, null);

        verify(jwkKeyRepository, times(1)).findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE);
    }
}
