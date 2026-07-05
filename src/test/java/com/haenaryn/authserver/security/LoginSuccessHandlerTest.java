package com.haenaryn.authserver.security;

import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import com.haenaryn.authserver.domain.user.LoginLockoutService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LoginSuccessHandlerTest {

    @Mock
    private LoginLockoutService loginLockoutService;
    @Mock
    private AuditLogService auditLogService;

    private LoginSuccessHandler handler;

    @BeforeEach
    void setUp() {
        handler = new LoginSuccessHandler(loginLockoutService, auditLogService);
        handler.setDefaultTargetUrl("/"); // 저장된 요청이 없을 때 리다이렉트할 기본 경로
    }

    @Test
    void onAuthenticationSuccess_delegates_reset_and_records_audit_log() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken("lee@haenaryn.com", "hashed");

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(loginLockoutService).resetFailureCounters("lee@haenaryn.com");
        verify(auditLogService).record(AuditEventType.LOGIN_SUCCESS, "lee@haenaryn.com", null);
        assertThat(response.getRedirectedUrl()).isEqualTo("/");
    }
}
