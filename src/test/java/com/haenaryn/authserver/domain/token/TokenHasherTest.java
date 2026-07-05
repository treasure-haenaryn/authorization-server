package com.haenaryn.authserver.domain.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    @Test
    void generateOpaqueToken_produces_url_safe_unpadded_base64_of_32_bytes() {
        String token = TokenHasher.generateOpaqueToken();

        assertThat(token).doesNotContain("+", "/", "=");
        // 32바이트 -> Base64 URL-safe(패딩 없음) 인코딩 시 43자
        assertThat(token).hasSize(43);
    }

    @Test
    void generateOpaqueToken_produces_different_values_each_call() {
        String first = TokenHasher.generateOpaqueToken();
        String second = TokenHasher.generateOpaqueToken();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void sha256_is_deterministic_for_the_same_input() {
        String hash1 = TokenHasher.sha256("raw-refresh-token-v1");
        String hash2 = TokenHasher.sha256("raw-refresh-token-v1");

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64); // SHA-256 -> 32바이트 -> hex 64자
    }

    @Test
    void sha256_produces_different_hashes_for_different_input() {
        String hash1 = TokenHasher.sha256("raw-refresh-token-v1");
        String hash2 = TokenHasher.sha256("raw-refresh-token-v2");

        assertThat(hash1).isNotEqualTo(hash2);
    }
}
