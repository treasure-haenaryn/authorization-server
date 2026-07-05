package com.haenaryn.authserver.domain.user;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 계정 잠금/자동 해제, 로그인 실패 폴백 카운터 등 User 엔티티 자체의 도메인 로직을 검증한다.
 * Spring 컨텍스트나 DB 없이 순수 단위 테스트로 충분한 영역.
 */
class UserTest {

    private User newUser() {
        return User.builder()
                .email("lee@haenaryn.com")
                .passwordHash("hashed-password")
                .name("Lee")
                .build();
    }

    @Test
    void builder_sets_sensible_defaults() {
        User user = newUser();

        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isAccountLocked()).isFalse();
        assertThat(user.getAccountLockedAt()).isNull();
    }

    @Test
    void lockAccount_sets_locked_flag_and_timestamp() {
        User user = newUser();

        user.lockAccount();

        assertThat(user.isAccountLocked()).isTrue();
        assertThat(user.getAccountLockedAt()).isNotNull();
    }

    @Test
    void unlockAccount_clears_locked_flag_and_timestamp() {
        User user = newUser();
        user.lockAccount();

        user.unlockAccount();

        assertThat(user.isAccountLocked()).isFalse();
        assertThat(user.getAccountLockedAt()).isNull();
    }

    @Test
    void isLockExpired_is_false_when_account_is_not_locked() {
        User user = newUser();

        assertThat(user.isLockExpired(1)).isFalse();
    }

    @Test
    void isLockExpired_is_false_before_window_elapses() {
        User user = newUser();
        user.lockAccount();

        // 잠긴 직후 24시간 윈도우는 아직 지나지 않았어야 한다
        assertThat(user.isLockExpired(24)).isFalse();
    }

    @Test
    void isLockExpired_is_true_once_window_has_elapsed() {
        User user = newUser();
        user.lockAccount();

        // windowHours=0 -> lockedAt + 0시간은 이미 과거이므로 즉시 만료로 판단되어야 한다
        assertThat(user.isLockExpired(0)).isTrue();
    }

    @Test
    void registerFailedLoginFallback_accumulates_within_window() {
        User user = newUser();

        int first = user.registerFailedLoginFallback(1);
        int second = user.registerFailedLoginFallback(1);

        assertThat(first).isEqualTo(1);
        assertThat(second).isEqualTo(2);
    }

    @Test
    void registerFailedLoginFallback_restarts_count_after_window_elapses() {
        User user = newUser();

        // windowHours=0 -> 매 호출마다 윈도우가 이미 지난 것으로 취급되어 1로 재시작해야 한다
        int first = user.registerFailedLoginFallback(0);
        int second = user.registerFailedLoginFallback(0);

        assertThat(first).isEqualTo(1);
        assertThat(second).isEqualTo(1);
    }

    @Test
    void resetFailedLoginFallback_clears_count_and_window() {
        User user = newUser();
        user.registerFailedLoginFallback(1);

        user.resetFailedLoginFallback();

        assertThat(user.getFailedLoginCount()).isEqualTo(0);
        assertThat(user.getFailedLoginWindowStartedAt()).isNull();
    }
}
