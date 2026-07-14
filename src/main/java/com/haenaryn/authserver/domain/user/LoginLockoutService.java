package com.haenaryn.authserver.domain.user;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 로그인 실패 카운터(Redis + PostgreSQL 폴백) 증가/리셋과 계정 잠금을 전담하는 서비스.
 */
@Service
public class LoginLockoutService {

    private static final Logger log = LoggerFactory.getLogger(LoginLockoutService.class);

    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private final AuthServerProperties properties;
    private final AuditLogService auditLogService;
    private final CircuitBreaker circuitBreaker;

    public LoginLockoutService(RedisTemplate<String, String> redisTemplate,
                                UserRepository userRepository,
                                AuthServerProperties properties,
                                AuditLogService auditLogService,
                                CircuitBreaker circuitBreaker) {
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
        this.properties = properties;
        this.auditLogService = auditLogService;
        this.circuitBreaker = circuitBreaker;
    }

    @Transactional
    public void registerFailure(String email) {
        try {
            circuitBreaker.executeRunnable(() -> registerFailureViaRedis(email));
        } catch (Exception e) {
            log.warn("Redis 장애/서킷 OPEN으로 로그인 실패 카운트 실패, PostgreSQL 폴백으로 전환: email={}", email, e);
            registerFailureViaDatabaseFallback(email);
        }

        auditLogService.record(AuditEventType.LOGIN_FAILURE, email, null);
    }

    @Transactional
    public void resetFailureCounters(String email) {
        try {
            circuitBreaker.executeRunnable(() -> redisTemplate.delete(RedisKeys.loginFail(email)));
        } catch (Exception e) {
            log.warn("Redis 장애로 로그인 실패 카운터 초기화 실패 (무시하고 진행): email={}", email, e);
        }

        userRepository.findByEmail(email).ifPresent(User::resetFailedLoginFallback);
    }

    private void registerFailureViaRedis(String email) {
        String key = RedisKeys.loginFail(email);
        Long count = redisTemplate.opsForValue().increment(key);

        if (count != null && count == 1L) {
            // 최초 실패일 때만 윈도우 TTL을 건다 (재설정하면 윈도우가 계속 밀림)
            redisTemplate.expire(key, RedisKeys.LOGIN_FAIL_TTL);
        }

        if (count != null && count >= properties.security().loginFailLockThreshold()) {
            userRepository.findByEmail(email).ifPresent(User::lockAccount);
            log.warn("로그인 {}회 연속 실패로 계정 잠금: email={}", count, email);
            auditLogService.record(AuditEventType.ACCOUNT_LOCKED, email, "source=redis,count=" + count);
        }
    }

    private void registerFailureViaDatabaseFallback(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            long windowHours = properties.security().loginFailWindowHours();
            int count = user.registerFailedLoginFallback(windowHours);

            if (count >= properties.security().loginFailLockThreshold()) {
                user.lockAccount();
                log.warn("[PostgreSQL 폴백] 로그인 {}회 연속 실패로 계정 잠금: email={}", count, email);
                auditLogService.record(AuditEventType.ACCOUNT_LOCKED, email,
                        "source=postgresql-fallback,count=" + count);
            }
        });
    }
}
