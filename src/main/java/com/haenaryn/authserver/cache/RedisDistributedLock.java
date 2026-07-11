package com.haenaryn.authserver.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

/**
 * {@code SET key value NX PX ttl} 기반의 단일 Redis 인스턴스용 분산 락.
 * 락 획득 실패/Redis 장애 시 fail-closed로 동작한다(빈 Optional 반환).
 */
@Component
public class RedisDistributedLock {

    private static final Logger log = LoggerFactory.getLogger(RedisDistributedLock.class);

    // KEYS[1]=lockKey, ARGV[1]=보유 토큰. 값이 일치할 때만 삭제(다른 인스턴스 락 오삭제 방지).
    private static final String UNLOCK_SCRIPT = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
            """;

    private final RedisTemplate<String, String> redisTemplate;
    private final DefaultRedisScript<Long> unlockScript;

    public RedisDistributedLock(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.unlockScript = new DefaultRedisScript<>(UNLOCK_SCRIPT, Long.class);
    }

    /** 락 획득 시도. 실패하면 {@link Optional#empty()} — 호출부는 작업을 건너뛰어야 한다. */
    public Optional<String> tryLock(String key, Duration ttl) {
        String token = UUID.randomUUID().toString();
        try {
            Boolean acquired = redisTemplate.opsForValue().setIfAbsent(key, token, ttl);
            if (Boolean.TRUE.equals(acquired)) {
                return Optional.of(token);
            }
            return Optional.empty();
        } catch (Exception e) {
            log.error("분산 락 획득 실패 (Redis 장애 가능성) — fail-closed로 이번 작업은 건너뜀: key={}", key, e);
            return Optional.empty();
        }
    }

    public void unlock(String key, String token) {
        try {
            redisTemplate.execute(unlockScript, Collections.singletonList(key), token);
        } catch (Exception e) {
            log.warn("분산 락 해제 실패 (TTL 만료로 자동 정리됨): key={}", key, e);
        }
    }
}
