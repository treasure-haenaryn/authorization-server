package com.haenaryn.authserver.domain.key;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class KeyRotationPolicyTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 7, 11, 12, 0);

    @Test
    void isRotationDue_true_when_activatedAt_is_null() {
        assertThat(KeyRotationPolicy.isRotationDue(null, Duration.ofDays(90), NOW)).isTrue();
    }

    @Test
    void isRotationDue_false_when_within_interval() {
        LocalDateTime activatedAt = NOW.minusDays(89);
        assertThat(KeyRotationPolicy.isRotationDue(activatedAt, Duration.ofDays(90), NOW)).isFalse();
    }

    @Test
    void isRotationDue_true_when_interval_exceeded() {
        LocalDateTime activatedAt = NOW.minusDays(91);
        assertThat(KeyRotationPolicy.isRotationDue(activatedAt, Duration.ofDays(90), NOW)).isTrue();
    }

    @Test
    void graceDeadline_adds_grace_period_to_now() {
        LocalDateTime deadline = KeyRotationPolicy.graceDeadline(NOW, Duration.ofMinutes(60));

        assertThat(deadline).isEqualTo(NOW.plusMinutes(60));
    }
}
