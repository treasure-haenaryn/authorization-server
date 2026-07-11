package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
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

/**
 * JWKS(/.well-known/jwks.json)와 {@code JwtDecoder}(/userinfo 검증)가 쓰는 검증 전용
 * 키 소스. ACTIVE + RETIRING 키를 모두 노출한다.
 */
@Component
public class RotatingVerificationJwkSource implements JWKSource<SecurityContext> {

    private static final List<KeyStatus> EXPOSED_STATUSES = List.of(KeyStatus.ACTIVE, KeyStatus.RETIRING);

    private final JwkKeyRepository jwkKeyRepository;
    private final TtlCache<JWKSet> cache;

    public RotatingVerificationJwkSource(JwkKeyRepository jwkKeyRepository, AuthServerProperties properties) {
        this.jwkKeyRepository = jwkKeyRepository;
        this.cache = new TtlCache<>(
                Duration.ofSeconds(properties.signingKey().cacheTtlSeconds()),
                this::loadJwkSet
        );
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        return jwkSelector.select(cache.get());
    }

    private JWKSet loadJwkSet() {
        List<JWK> jwks = jwkKeyRepository.findAllByStatusIn(EXPOSED_STATUSES).stream()
                .map(this::toPublicJwk)
                .toList();
        return new JWKSet(jwks);
    }

    private JWK toPublicJwk(JwkKeyEntity entity) {
        try {
            return ECKey.parse(entity.getPublicKey());
        } catch (ParseException e) {
            throw new IllegalStateException(
                    "jwk_keys.id=" + entity.getId() + " public_key 파싱 실패 — 데이터가 손상되었을 수 있습니다.", e);
        }
    }
}
