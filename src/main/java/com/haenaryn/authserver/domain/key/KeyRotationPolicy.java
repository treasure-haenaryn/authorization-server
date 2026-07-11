package com.haenaryn.authserver.domain.key;

import java.time.Duration;
import java.time.LocalDateTime;

/** 로테이션 시점 판단용 순수 함수 모음. */
public final class KeyRotationPolicy {

    private KeyRotationPolicy() {
    }

    /** ACTIVE 키가 rotationInterval을 넘겼는지 — 자동 로테이션 스케줄러가 사용. */
    public static boolean isRotationDue(LocalDateTime activatedAt, Duration rotationInterval, LocalDateTime now) {
        if (activatedAt == null) {
            return true;
        }
        return activatedAt.plus(rotationInterval).isBefore(now);
    }

    /** RETIRING으로 전환되는 시점 기준 grace period 종료 시각. */
    public static LocalDateTime graceDeadline(LocalDateTime now, Duration gracePeriod) {
        return now.plus(gracePeriod);
    }
}
