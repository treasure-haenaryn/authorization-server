package com.haenaryn.authserver.security;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;

/**
 * 로그인 실패 시 Redis 카운터를 증가시키고 임계값 도달 시 계정을 잠근다.
 * Redis 장애 시에는 PostgreSQL(User 엔티티)로 폴백한다.
 */
@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginFailureHandler.class);

    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private final AuthServerProperties properties;
    private final AuditLogService auditLogService;

    public LoginFailureHandler(RedisTemplate<String, String> redisTemplate,
                                UserRepository userRepository,
                                AuthServerProperties properties,
                                AuditLogService auditLogService) {
        super("/login?error");
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
        this.properties = properties;
        this.auditLogService = auditLogService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException, ServletException {
        String email = request.getParameter("username");
        if (email != null && !email.isBlank()) {
            registerFailure(email);
        }
        super.onAuthenticationFailure(request, response, exception);
    }

    @Transactional
    void registerFailure(String email) {
        try {
            registerFailureViaRedis(email);
        } catch (Exception e) {
            log.warn("Redis 장애로 로그인 실패 카운트 실패, PostgreSQL 폴백으로 전환: email={}", email, e);
            registerFailureViaDatabaseFallback(email);
        }

        auditLogService.record(AuditEventType.LOGIN_FAILURE, email, null);
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
