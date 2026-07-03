package com.haenaryn.authserver.cache;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class RedisKeysTest {

    @Test
    void refreshToken_key_format() {
        assertThat(RedisKeys.refreshToken("token-123")).isEqualTo("refresh_token:token-123");
        assertThat(RedisKeys.REFRESH_TOKEN_TTL).isEqualTo(Duration.ofDays(7));
    }

    @Test
    void blacklist_key_format() {
        assertThat(RedisKeys.blacklist("jti-abc")).isEqualTo("blacklist:jti-abc");
        assertThat(RedisKeys.BLACKLIST_TTL).isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void authCode_key_format() {
        assertThat(RedisKeys.authCode("code-xyz")).isEqualTo("auth_code:code-xyz");
        assertThat(RedisKeys.AUTH_CODE_TTL).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void loginFail_key_format() {
        assertThat(RedisKeys.loginFail("lee@haenaryn.com")).isEqualTo("login_fail:lee@haenaryn.com");
        assertThat(RedisKeys.LOGIN_FAIL_TTL).isEqualTo(Duration.ofHours(1));
    }
}
