-- Phase5: 보안 감사 이벤트 저장소. 로그인 성공/실패, 로그아웃, Refresh Token
-- 발급/재발급/재사용감지/폐기처럼 "누가 언제 무엇을" 조회해야 하는 이벤트만 여기 저장한다.
-- Redis 장애, Rate Limit 차단, 예외 등 운영/장애 분석용 이벤트는 여기 저장하지 않고
-- 구조화 로그(JSON)로만 남긴다 — Phase5_작업계획.md 참고.
CREATE TABLE audit_logs
(
    id          BIGSERIAL PRIMARY KEY,
    event_type  VARCHAR(50) NOT NULL,
    principal   VARCHAR(255),          -- 사용자 이메일. 시스템/식별 불가 이벤트는 NULL
    ip_address  VARCHAR(45),
    detail      TEXT,                  -- 이벤트별 부가 정보 (JSON 문자열, 애플리케이션에서 수동 조립)
    occurred_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_principal ON audit_logs (principal);
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_occurred_at ON audit_logs (occurred_at);

COMMENT ON TABLE audit_logs IS '보안 감사 이벤트 (로그인 성공/실패, 로그아웃, Refresh Token 발급/재발급/재사용감지/폐기)';
COMMENT ON COLUMN audit_logs.event_type IS 'LOGIN_SUCCESS / LOGIN_FAILURE / ACCOUNT_LOCKED / LOGOUT / REFRESH_TOKEN_ISSUED / REFRESH_TOKEN_ROTATED / REFRESH_TOKEN_REUSE_DETECTED / REFRESH_TOKEN_REVOKED';
