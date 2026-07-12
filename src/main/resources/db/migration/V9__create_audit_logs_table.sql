-- Phase5: 보안 감사 이벤트 저장소. 로그인 성공/실패, 로그아웃, Refresh Token
-- 발급/재발급/재사용감지/폐기처럼 "누가 언제 무엇을" 조회해야 하는 이벤트만 여기 저장한다.
-- Redis 장애, Rate Limit 차단, 예외 등 운영/장애 분석용 이벤트는 여기 저장하지 않고
-- 구조화 로그(JSON)로만 남긴다
--
-- occurred_at 기준 월별 RANGE 파티션 테이블로 처음부터 생성한다. 파티션 키가 PK에
-- 포함돼야 하는 PostgreSQL 제약 때문에 PK는 (id, occurred_at) 복합키다. 실제 파티션
-- 생성/보존 기간 관리는 V11의 pg_partman 설정이 담당한다.
CREATE TABLE audit_logs
(
    id          BIGSERIAL,
    event_type  VARCHAR(50) NOT NULL,
    principal   VARCHAR(255),          -- 사용자 이메일. 시스템/식별 불가 이벤트는 NULL
    ip_address  VARCHAR(45),
    detail      TEXT,                  -- 이벤트별 부가 정보 (JSON 문자열, 애플리케이션에서 수동 조립)
    occurred_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX idx_audit_logs_principal ON audit_logs (principal);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_occurred_at ON audit_logs (occurred_at);

COMMENT ON TABLE audit_logs IS '보안 감사 이벤트 (occurred_at 기준 월별 RANGE 파티션, 파티션 생성/정리는 pg_partman이 관리)';
COMMENT ON COLUMN audit_logs.event_type IS 'LOGIN_SUCCESS / LOGIN_FAILURE / ACCOUNT_LOCKED / LOGOUT / REFRESH_TOKEN_ISSUED / REFRESH_TOKEN_ROTATED / REFRESH_TOKEN_REUSE_DETECTED / REFRESH_TOKEN_REVOKED';
