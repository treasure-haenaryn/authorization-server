package com.haenaryn.authserver.domain.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger("AUDIT");

    private final ApplicationEventPublisher eventPublisher;

    public AuditLogService(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public void record(AuditEventType eventType, String principal, String detail) {
        String ipAddress = resolveClientIp();
        log.info("event_type={} principal={} ip={} detail={}", eventType, principal, ipAddress, detail);
        eventPublisher.publishEvent(new AuditEvent(eventType, principal, ipAddress, detail));
    }

    private String resolveClientIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest().getRemoteAddr();
        }
        return null;
    }
}
