package com.haenaryn.authserver.domain.audit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 * 감사 로그 이벤트 발행 + 요청 컨텍스트로부터의 클라이언트 IP 추출을 검증한다.
 * DB/구조화 로그 기록 자체는 이벤트 리스너(AuditEventListener) 쪽 책임이라 여기선 이벤트 발행만 검증한다.
 */
@ExtendWith(MockitoExtension.class)
class AuditLogServiceTest {

    @Mock
    private ApplicationEventPublisher eventPublisher;

    private AuditLogService auditLogService;

    @BeforeEach
    void setUp() {
        auditLogService = new AuditLogService(eventPublisher);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void record_resolves_client_ip_from_current_request_when_present() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.0.10");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        auditLogService.record(AuditEventType.LOGIN_SUCCESS, "lee@haenaryn.com", "detail");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());

        AuditEvent event = captor.getValue();
        assertThat(event.eventType()).isEqualTo(AuditEventType.LOGIN_SUCCESS);
        assertThat(event.principal()).isEqualTo("lee@haenaryn.com");
        assertThat(event.ipAddress()).isEqualTo("192.168.0.10");
        assertThat(event.detail()).isEqualTo("detail");
    }

    @Test
    void record_leaves_ip_null_when_no_request_context_is_active() {
        auditLogService.record(AuditEventType.LOGOUT, "lee@haenaryn.com", null);

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(eventPublisher).publishEvent(captor.capture());

        assertThat(captor.getValue().ipAddress()).isNull();
    }
}
