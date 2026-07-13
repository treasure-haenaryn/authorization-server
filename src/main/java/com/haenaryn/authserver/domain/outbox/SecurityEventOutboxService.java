package com.haenaryn.authserver.domain.outbox;

import com.haenaryn.authserver.domain.audit.AuditEventType;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 도메인 트랜잭션 안에서 직접 호출해 같은 트랜잭션으로 커밋되게 하는 아웃박스 기록기.
 * {@code AuditLogService}(AFTER_COMMIT, best-effort)와 달리 유실이 허용되지 않는 이벤트용.
 */
@Service
public class SecurityEventOutboxService {

    private final SecurityEventOutboxRepository repository;

    public SecurityEventOutboxService(SecurityEventOutboxRepository repository) {
        this.repository = repository;
    }

    public void record(AuditEventType eventType, String principal, Map<String, String> payloadFields) {
        SecurityEventOutbox outbox = SecurityEventOutbox.builder()
                .eventType(eventType)
                .principal(principal)
                .payload(toJson(payloadFields))
                .build();
        repository.save(outbox);
    }

    private String toJson(Map<String, String> fields) {
        Map<String, String> safeFields = fields != null ? fields : new LinkedHashMap<>();
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : safeFields.entrySet()) {
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("\"").append(escape(entry.getKey())).append("\":")
                    .append("\"").append(escape(entry.getValue())).append("\"");
        }
        return json.append("}").toString();
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
