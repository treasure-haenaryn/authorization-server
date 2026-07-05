package com.haenaryn.authserver.domain.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 트랜잭션 커밋 이후(AFTER_COMMIT) 감사 이벤트를 audit_logs 테이블에 저장하는 리스너 검증.
 */
@ExtendWith(MockitoExtension.class)
class AuditEventListenerTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    private AuditEventListener listener;

    @BeforeEach
    void setUp() {
        listener = new AuditEventListener(auditLogRepository);
    }

    @Test
    void onAuditEvent_persists_event_fields_as_audit_log() {
        AuditEvent event = new AuditEvent(AuditEventType.LOGIN_SUCCESS, "lee@haenaryn.com", "127.0.0.1", "detail");

        listener.onAuditEvent(event);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertThat(saved.getEventType()).isEqualTo(AuditEventType.LOGIN_SUCCESS);
        assertThat(saved.getPrincipal()).isEqualTo("lee@haenaryn.com");
        assertThat(saved.getIpAddress()).isEqualTo("127.0.0.1");
        assertThat(saved.getDetail()).isEqualTo("detail");
    }

    @Test
    void onAuditEvent_swallows_repository_failure_instead_of_propagating() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("DB down"));
        AuditEvent event = new AuditEvent(AuditEventType.LOGOUT, "lee@haenaryn.com", "127.0.0.1", null);

        assertDoesNotThrow(() -> listener.onAuditEvent(event));
    }
}
