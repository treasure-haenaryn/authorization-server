package com.haenaryn.authserver.domain.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * 바깥 트랜잭션이 실제로 커밋된 이후에만 {@code audit_logs}에 저장한다.
 */
@Component
public class AuditEventListener {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    private final AuditLogRepository auditLogRepository;

    public AuditEventListener(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onAuditEvent(AuditEvent event) {
        try {
            auditLogRepository.save(AuditLog.builder()
                    .eventType(event.eventType())
                    .principal(event.principal())
                    .ipAddress(event.ipAddress())
                    .detail(event.detail())
                    .build());
        } catch (Exception e) {
            log.error("감사 로그 DB 저장 실패 (구조화 로그로는 이미 기록됨): eventType={}, principal={}",
                    event.eventType(), event.principal(), e);
        }
    }
}
