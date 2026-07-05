package com.haenaryn.authserver.domain.user;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 로그인 실패 카운터(Redis + PostgreSQL 폴백) 증가/리셋과 계정 잠금을 전담하는 서비스.
 *
 * <p>원래 이 로직은 {@code LoginFailureHandler}/{@code LoginSuccessHandler} 안에 있었는데,
 * {@code onAuthenticationFailure()}가 같은 클래스의 {@code registerFailure()}를 직접 호출하는
 * self-invocation 구조라 {@code @Transactional}이 Spring AOP 프록시를 우회해 실제로는 전혀
 * 적용되지 않았다. {@code spring.jpa.open-in-view=false}와 맞물려, 트랜잭션 없이 엔티티
 * 필드만 바뀌고 DB에는 절대 반영되지 않는 버그로 이어졌다(계정 잠금이 저장 안 됨).
 *
 * <p>이 로직을 별도 빈으로 분리하면 핸들러가 이 서비스를 "외부에서" 호출하게 되어
 * Spring이 만든 트랜잭션 프록시를 정상적으로 거치고, {@code @Transactional}이 진짜로 동작한다.
 * 그 결과 {@code findByEmail()}로 조회한 엔티티가 트랜잭션이 끝날 때까지 영속 상태로 남아
 * JPA 더티 체킹이 알아서 UPDATE를 flush해주므로, 명시적 {@code save()} 호출도 필요 없어진다.</p>
 */
@Service
public class LoginLockoutService {

    private static final Logger log = LoggerFactory.getLogger(LoginLockoutService.class);

    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private final AuthServerProperties properties;
    private final AuditLogService auditLogService;

    public LoginLockoutService(RedisTemplate<String, String> redisTemplate,
                                UserRepository userRepository,
                                AuthServerProperties properties,
                                AuditLogService auditLogService) {
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
        this.properties = properties;
        this.auditLogService = auditLogService;
    }

    @Transactional
    public void registerFailure(String email) {
        try {
            registerFailureViaRedis(email);
        } catch (Exception e) {
            log.warn("Redis 장애로 로그인 실패 카운트 실패, PostgreSQL 폴백으로 전환: email={}", email, e);
            registerFailureViaDatabaseFallback(email);
        }

        auditLogService.record(AuditEventType.LOGIN_FAILURE, email, null);
    }

    @Transactional
    public void resetFailureCounters(String email) {
        try {
            redisTemplate.delete(RedisKeys.loginFail(email));
        } catch (Exception e) {
            log.warn("Redis 장애로 로그인 실패 카운터 초기화 실패 (무시하고 진행): email={}", email, e);
        }

        // 이 메서드가 실제로 트랜잭션 안에서 실행되므로(외부에서 프록시를 거쳐 호출됨),
        // findByEmail()로 조회한 user는 영속 상태로 유지되고 resetFailedLoginFallback()으로
        // 바뀐 필드는 트랜잭션 커밋 시 JPA 더티 체킹이 자동으로 flush한다. save() 불필요.
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
            // 이 메서드도 registerFailure()의 @Transactional 안에서 실행되므로(정상적으로 프록시를
            // 거쳐 호출됨), 잠금 여부와 무관하게 카운터 증가분은 트랜잭션 커밋 시 자동 flush된다.
        });
    }
}
