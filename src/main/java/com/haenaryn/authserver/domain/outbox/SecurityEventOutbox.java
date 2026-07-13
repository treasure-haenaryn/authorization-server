package com.haenaryn.authserver.domain.outbox;

import com.haenaryn.authserver.domain.audit.AuditEventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/** 도메인 트랜잭션과 원자적으로 커밋되는 보안 이벤트 아웃박스 행. */
@Entity
@Table(name = "security_event_outbox")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SecurityEventOutbox {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private AuditEventType eventType;

    @Column(nullable = false, length = 255)
    private String principal;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String payload;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private OutboxStatus status;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "published_at")
    private LocalDateTime publishedAt;

    @Column(nullable = false)
    private int attempts;

    @Builder
    private SecurityEventOutbox(AuditEventType eventType, String principal, String payload) {
        this.eventType = eventType;
        this.principal = principal;
        this.payload = payload;
        this.status = OutboxStatus.PENDING;
        this.attempts = 0;
    }

    /** relay가 전송 성공 후 호출. */
    public void markPublished() {
        this.status = OutboxStatus.PUBLISHED;
        this.publishedAt = LocalDateTime.now();
    }

    /** relay가 전송 실패 시 호출. 재시도 정책(최대 횟수 등)은 relay 쪽 책임. */
    public void markFailed() {
        this.status = OutboxStatus.FAILED;
        this.attempts++;
    }
}
