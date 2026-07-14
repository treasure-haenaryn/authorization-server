package com.haenaryn.authserver.cache;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * 락 획득/해제가 fail-closed로 동작하는지 검증한다 — Rate limit/블랙리스트(fail-open)와 달리
 * 이 락은 Redis 장애/서킷 OPEN 시 "락 없이 진행"이 아니라 "이번 작업은 건너뜀"이어야 한다.
 */
@ExtendWith(MockitoExtension.class)
class RedisDistributedLockTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private CircuitBreaker circuitBreaker;
    private RedisDistributedLock lock;

    @BeforeEach
    void setUp() {
        circuitBreaker = CircuitBreaker.ofDefaults("test");
        lock = new RedisDistributedLock(redisTemplate, circuitBreaker);
    }

    @Test
    void tryLock_returns_token_when_acquired() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.setIfAbsent(eq("lock:test"), anyString(), any(Duration.class))).thenReturn(true);

        Optional<String> token = lock.tryLock("lock:test", Duration.ofSeconds(30));

        assertThat(token).isPresent();
    }

    @Test
    void tryLock_returns_empty_when_already_held_by_another_instance() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.setIfAbsent(eq("lock:test"), anyString(), any(Duration.class))).thenReturn(false);

        Optional<String> token = lock.tryLock("lock:test", Duration.ofSeconds(30));

        assertThat(token).isEmpty();
    }

    @Test
    void tryLock_fails_closed_when_redis_throws() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis connection refused"));

        Optional<String> token = lock.tryLock("lock:test", Duration.ofSeconds(30));

        assertThat(token).isEmpty();
    }

    @Test
    void unlock_does_not_throw_when_redis_fails() {
        when(redisTemplate.execute(any(RedisScript.class), eq(List.of("lock:test")), any()))
                .thenThrow(new RuntimeException("Redis connection refused"));

        assertThatCode(() -> lock.unlock("lock:test", "some-token")).doesNotThrowAnyException();
    }

    @Test
    void tryLock_fails_closed_when_circuit_breaker_is_open_without_even_calling_redis() {
        // Redis가 "느려지기만" 해서 서킷이 OPEN된 상황 — 타임아웃을 기다리지 않고 바로 스킵돼야 한다.
        circuitBreaker.transitionToOpenState();

        Optional<String> token = lock.tryLock("lock:test", Duration.ofSeconds(30));

        assertThat(token).isEmpty();
        verifyNoInteractions(redisTemplate);
    }
}
