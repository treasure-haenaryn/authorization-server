package com.haenaryn.authserver.domain.user;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 로그인 실패 시 Redis 카운터 증가/임계값 도달 시 계정 잠금, Redis 장애 시 PostgreSQL 폴백,
 * 그리고 로그인 성공 시 카운터 리셋이 정확히 동작하는지 검증한다.
 */
@ExtendWith(MockitoExtension.class)
class LoginLockoutServiceTest {

    private static final AuthServerProperties.Security SECURITY =
            new AuthServerProperties.Security(5, 1, false);

    @Mock
    private RedisTemplate<String, String> redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private UserRepository userRepository;
    @Mock
    private AuditLogService auditLogService;

    private LoginLockoutService service;

    @BeforeEach
    void setUp() {
        AuthServerProperties properties = new AuthServerProperties(null, null, SECURITY, null, null);
        service = new LoginLockoutService(redisTemplate, userRepository, properties, auditLogService);
    }

    @Test
    void registerFailure_increments_counter_and_sets_ttl_only_on_first_failure() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment("login_fail:lee@haenaryn.com")).thenReturn(1L);

        service.registerFailure("lee@haenaryn.com");

        verify(redisTemplate).expire("login_fail:lee@haenaryn.com", Duration.ofHours(1));
        verify(userRepository, never()).findByEmail(anyString());
        verify(auditLogService).record(AuditEventType.LOGIN_FAILURE, "lee@haenaryn.com", null);
    }

    @Test
    void registerFailure_does_not_reset_ttl_after_first_failure() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment("login_fail:lee@haenaryn.com")).thenReturn(3L);

        service.registerFailure("lee@haenaryn.com");

        // 매 실패마다 TTL을 갱신하면 "1시간 내 5회"가 아니라 "마지막 실패로부터 항상 1시간"이 되어버리므로
        // 최초 실패(count==1)가 아닐 때는 expire를 다시 호출하면 안 된다.
        verify(redisTemplate, never()).expire(anyString(), any(Duration.class));
    }

    @Test
    void registerFailure_locks_account_when_threshold_reached_via_redis() {
        User user = User.builder().email("lee@haenaryn.com").passwordHash("hashed").build();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment("login_fail:lee@haenaryn.com")).thenReturn(5L);
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        service.registerFailure("lee@haenaryn.com");

        assertThat(user.isAccountLocked()).isTrue();
        verify(auditLogService).record(eq(AuditEventType.ACCOUNT_LOCKED), eq("lee@haenaryn.com"), contains("source=redis"));
    }

    @Test
    void registerFailure_does_not_lock_before_threshold() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment("login_fail:lee@haenaryn.com")).thenReturn(4L);

        service.registerFailure("lee@haenaryn.com");

        verify(userRepository, never()).findByEmail(anyString());
        verify(auditLogService, never()).record(eq(AuditEventType.ACCOUNT_LOCKED), anyString(), anyString());
    }

    @Test
    void registerFailure_falls_back_to_postgresql_when_redis_throws() {
        User user = User.builder().email("lee@haenaryn.com").passwordHash("hashed").build();
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis connection refused"));
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        // threshold=5이므로 5번 호출해야 잠긴다 (폴백 카운터는 User 엔티티 안에 누적됨)
        for (int i = 0; i < 5; i++) {
            service.registerFailure("lee@haenaryn.com");
        }

        assertThat(user.isAccountLocked()).isTrue();
        assertThat(user.getFailedLoginCount()).isEqualTo(5);
        verify(auditLogService).record(eq(AuditEventType.ACCOUNT_LOCKED), eq("lee@haenaryn.com"), contains("source=postgresql-fallback"));
    }

    @Test
    void registerFailure_via_fallback_when_user_not_found_does_not_throw() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis connection refused"));
        when(userRepository.findByEmail("ghost@haenaryn.com")).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service.registerFailure("ghost@haenaryn.com"));
    }

    @Test
    void resetFailureCounters_deletes_redis_key_and_resets_fallback_counter() {
        User user = userWithPriorFailures();
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        service.resetFailureCounters("lee@haenaryn.com");

        verify(redisTemplate).delete(RedisKeys.loginFail("lee@haenaryn.com"));
        assertThat(user.getFailedLoginCount()).isEqualTo(0);
    }

    @Test
    void resetFailureCounters_still_resets_fallback_counter_when_redis_delete_throws() {
        User user = userWithPriorFailures();
        doThrow(new RuntimeException("Redis connection refused"))
                .when(redisTemplate).delete(RedisKeys.loginFail("lee@haenaryn.com"));
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        assertDoesNotThrow(() -> service.resetFailureCounters("lee@haenaryn.com"));

        assertThat(user.getFailedLoginCount()).isEqualTo(0);
    }

    private User userWithPriorFailures() {
        User user = User.builder().email("lee@haenaryn.com").passwordHash("hashed").build();
        user.registerFailedLoginFallback(1);
        return user;
    }
}
