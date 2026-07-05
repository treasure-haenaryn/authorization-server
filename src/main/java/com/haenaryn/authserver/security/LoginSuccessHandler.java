package com.haenaryn.authserver.security;

import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import com.haenaryn.authserver.domain.user.LoginLockoutService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 로그인 성공 시 로그인 실패 카운터(Redis + PostgreSQL 폴백) 리셋을 {@link LoginLockoutService}에
 * 위임한다. 리다이렉트는 기본 동작(직전 요청 URL)을 유지하기 위해 부모 클래스를 상속한다.
 */
@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final LoginLockoutService loginLockoutService;
    private final AuditLogService auditLogService;

    public LoginSuccessHandler(LoginLockoutService loginLockoutService, AuditLogService auditLogService) {
        this.loginLockoutService = loginLockoutService;
        this.auditLogService = auditLogService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws ServletException, IOException {
        String email = authentication.getName();
        loginLockoutService.resetFailureCounters(email);
        auditLogService.record(AuditEventType.LOGIN_SUCCESS, email, null);
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
