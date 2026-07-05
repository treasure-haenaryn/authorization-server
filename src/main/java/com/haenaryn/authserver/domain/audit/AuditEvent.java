package com.haenaryn.authserver.domain.audit;

/**
 * {@link AuditLogService}가 발행하는 감사 이벤트 페이로드.
 */
public record AuditEvent(AuditEventType eventType, String principal, String ipAddress, String detail) {
}
