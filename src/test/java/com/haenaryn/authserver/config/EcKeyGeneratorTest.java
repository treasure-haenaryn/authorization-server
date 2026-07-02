package com.haenaryn.authserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EcKeyGeneratorTest {

    @Test
    void generate_returns_valid_p256_ec_key_with_private_part() {
        ECKey key = EcKeyGenerator.generate();

        assertThat(key.getKeyID()).isNotBlank();
        assertThat(key.isPrivate()).isTrue();
        assertThat(key.getCurve()).isEqualTo(Curve.P_256);
    }

    @Test
    void generate_produces_different_keys_each_call() throws JOSEException {
        ECKey first = EcKeyGenerator.generate();
        ECKey second = EcKeyGenerator.generate();

        assertThat(first.getKeyID()).isNotEqualTo(second.getKeyID());
        assertThat(first.toECPublicKey()).isNotEqualTo(second.toECPublicKey());
    }
}
