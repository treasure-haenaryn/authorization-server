package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.cache.RedisDistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/** 서명키 자동 로테이션/폐기 스케줄러. {@code source=database}일 때만 동작한다. */
@Component
@ConditionalOnProperty(prefix = "auth-server.signing-key", name = "source", havingValue = "database")
public class KeyRotationScheduler {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationScheduler.class);

    private static final String ROTATE_LOCK_KEY = "lock:jwk:rotate";
    private static final String SWEEP_LOCK_KEY = "lock:jwk:sweep";
    private static final Duration LOCK_TTL = Duration.ofMinutes(5);

    private final KeyRotationService keyRotationService;
    private final RedisDistributedLock lock;

    public KeyRotationScheduler(KeyRotationService keyRotationService, RedisDistributedLock lock) {
        this.keyRotationService = keyRotationService;
        this.lock = lock;
    }

    /** 매일 03:00 — ACTIVE 키가 rotation-interval-days를 넘겼으면 자동 로테이션. */
    @Scheduled(cron = "${auth-server.signing-key.rotation-check-cron:0 0 3 * * *}")
    public void checkAndRotate() {
        if (!keyRotationService.isRotationDue()) {
            return;
        }
        withLock(ROTATE_LOCK_KEY, () -> keyRotationService.rotate("scheduled"));
    }

    /** 매시 정각 — grace period가 지난 RETIRING 키를 RETIRED로 정리. */
    @Scheduled(cron = "${auth-server.signing-key.sweep-cron:0 0 * * * *}")
    public void sweep() {
        withLock(SWEEP_LOCK_KEY, keyRotationService::sweepExpiredRetiring);
    }

    private void withLock(String lockKey, Runnable action) {
        Optional<String> token = lock.tryLock(lockKey, LOCK_TTL);
        if (token.isEmpty()) {
            log.info("락 획득 실패 — 다른 인스턴스가 처리 중이거나 Redis 장애로 이번 주기는 건너뜀: lockKey={}", lockKey);
            return;
        }
        try {
            action.run();
        } catch (Exception e) {
            log.error("스케줄 작업 실행 중 오류: lockKey={}", lockKey, e);
        } finally {
            lock.unlock(lockKey, token.get());
        }
    }
}
