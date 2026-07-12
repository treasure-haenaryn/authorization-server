package com.haenaryn.authserver.domain.retention;

import com.haenaryn.authserver.cache.RedisDistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/** audit_logs/refresh_token_histories 파티션의 사전 생성/보존 기간 정리를 도는 스케줄러. */
@Component
public class DataRetentionScheduler {

    private static final Logger log = LoggerFactory.getLogger(DataRetentionScheduler.class);

    private static final String LOCK_KEY = "lock:retention:partition-maintenance";
    private static final Duration LOCK_TTL = Duration.ofMinutes(10);

    private final DataRetentionService dataRetentionService;
    private final RedisDistributedLock lock;

    public DataRetentionScheduler(DataRetentionService dataRetentionService, RedisDistributedLock lock) {
        this.dataRetentionService = dataRetentionService;
        this.lock = lock;
    }

    /** 매일 04:00 — 향후 파티션 준비 + 보존 기간 지난 파티션 정리. */
    @Scheduled(cron = "${auth-server.retention.purge-cron:0 0 4 * * *}")
    public void maintainPartitions() {
        Optional<String> token = lock.tryLock(LOCK_KEY, LOCK_TTL);
        if (token.isEmpty()) {
            log.info("락 획득 실패 — 다른 인스턴스가 처리 중이거나 Redis 장애로 이번 주기는 건너뜀");
            return;
        }
        try {
            dataRetentionService.runPartitionMaintenance();
        } catch (Exception e) {
            log.error("파티션 유지보수 중 오류", e);
        } finally {
            lock.unlock(LOCK_KEY, token.get());
        }
    }
}
