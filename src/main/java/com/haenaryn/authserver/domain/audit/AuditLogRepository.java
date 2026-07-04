package com.haenaryn.authserver.domain.audit;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findAllByPrincipalOrderByOccurredAtDesc(String principal);

    List<AuditLog> findAllByEventTypeOrderByOccurredAtDesc(AuditEventType eventType);
}
