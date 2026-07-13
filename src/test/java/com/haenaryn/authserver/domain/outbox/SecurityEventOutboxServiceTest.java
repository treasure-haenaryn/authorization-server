package com.haenaryn.authserver.domain.outbox;

import com.haenaryn.authserver.domain.audit.AuditEventType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityEventOutboxServiceTest {

    @Mock
    private SecurityEventOutboxRepository repository;

    private SecurityEventOutboxService service;

    @Test
    void record_saves_pending_row_with_json_payload() {
        service = new SecurityEventOutboxService(repository);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("familyId", "family-1");
        fields.put("ipAddress", "127.0.0.1");

        service.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, "lee@haenaryn.com", fields);

        ArgumentCaptor<SecurityEventOutbox> captor = ArgumentCaptor.forClass(SecurityEventOutbox.class);
        verify(repository).save(captor.capture());

        SecurityEventOutbox saved = captor.getValue();
        assertThat(saved.getEventType()).isEqualTo(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED);
        assertThat(saved.getPrincipal()).isEqualTo("lee@haenaryn.com");
        assertThat(saved.getStatus()).isEqualTo(OutboxStatus.PENDING);
        assertThat(saved.getPayload()).isEqualTo("{\"familyId\":\"family-1\",\"ipAddress\":\"127.0.0.1\"}");
    }

    @Test
    void record_escapes_quotes_and_backslashes_in_field_values() {
        service = new SecurityEventOutboxService(repository);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("deviceInfo", "Mozilla/5.0 \"weird\" agent\\test");

        service.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, "lee@haenaryn.com", fields);

        ArgumentCaptor<SecurityEventOutbox> captor = ArgumentCaptor.forClass(SecurityEventOutbox.class);
        verify(repository).save(captor.capture());

        assertThat(captor.getValue().getPayload())
                .isEqualTo("{\"deviceInfo\":\"Mozilla/5.0 \\\"weird\\\" agent\\\\test\"}");
    }

    @Test
    void record_handles_null_payload_map_as_empty_object() {
        service = new SecurityEventOutboxService(repository);

        service.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, "lee@haenaryn.com", null);

        ArgumentCaptor<SecurityEventOutbox> captor = ArgumentCaptor.forClass(SecurityEventOutbox.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getPayload()).isEqualTo("{}");
    }
}
