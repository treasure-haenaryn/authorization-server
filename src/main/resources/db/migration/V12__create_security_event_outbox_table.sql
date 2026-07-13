-- 보안 이벤트 아웃박스. 감지 트랜잭션과 원자적으로 커밋되고, 실제 알림 발송(Slack/Kafka 등)은
-- 이 테이블을 읽는 별도 relay가 담당한다(아직 미구현 — 이번 마이그레이션은 적재까지만).

CREATE TABLE security_event_outbox
(
    id           BIGSERIAL PRIMARY KEY,
    event_type   VARCHAR(50)  NOT NULL,
    principal    VARCHAR(255) NOT NULL,
    payload      TEXT         NOT NULL, -- JSON 문자열
    status       VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    attempts     INT          NOT NULL DEFAULT 0,

    CONSTRAINT chk_security_event_outbox_status CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED'))
);

-- 향후 relay가 "PENDING을 오래된 순으로" 조회할 때 사용
CREATE INDEX idx_security_event_outbox_status_created_at ON security_event_outbox (status, created_at);

COMMENT ON TABLE security_event_outbox IS '아웃박스 패턴: 도메인 트랜잭션과 함께 커밋, relay가 나중에 실제 전송';
