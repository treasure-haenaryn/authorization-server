package com.haenaryn.authserver.security;

import com.haenaryn.authserver.cache.RedisKeys;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;

/**
 * 로그인 성공 시 로그인 실패 카운터(Redis + PostgreSQL 폴백)를 모두 초기화한다.
 * 리다이렉트는 기본 동작(직전 요청 URL)을 유지하기 위해 부모 클래스를 상속한다.
 */
@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(LoginSuccessHandler.class);

    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    public LoginSuccessHandler(RedisTemplate<String, String> redisTemplate,
                                UserRepository userRepository,
                                AuditLogService auditLogService) {
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws ServletException, IOException {
        String email = authentication.getName();
        resetFailureCounters(email);
        auditLogService.record(AuditEventType.LOGIN_SUCCESS, email, null);
        super.onAuthenticationSuccess(request, response, authentication);
    }

    @Transactional
    void resetFailureCounters(String email) {
        try {
            redisTemplate.delete(RedisKeys.loginFail(email));
        } catch (Exception e) {
            log.warn("Redis 장애로 로그인 실패 카운터 초기화 실패 (무시하고 진행): email={}", email, e);
        }

        userRepository.findByEmail(email).ifPresent(User::resetFailedLoginFallback);
    }
}
