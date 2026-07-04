CREATE TABLE refresh_tokens
(
    id           BIGSERIAL PRIMARY KEY,
    token_hash   VARCHAR(64)  NOT NULL, -- SHA-256 해시 (hex, 64자) — 원문 미저장
    family_id    VARCHAR(36)  NOT NULL, -- 로그인 시점마다 발급되는 UUID. 재사용 감지 시 이 값 기준으로 체인 전체를 폐기
    user_id      BIGINT       NOT NULL REFERENCES users (id),
    client_id    VARCHAR(100) NOT NULL, -- oauth2_registered_client.client_id
    device_info  VARCHAR(255),
    ip_address   VARCHAR(45),           -- IPv6 대비 45자
    issued_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TIMESTAMP    NOT NULL,
    revoked      BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at   TIMESTAMP,
    revoked_by   VARCHAR(100),          -- 관리자 ID 등 폐기 주체

    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens (revoked);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);

COMMENT ON TABLE refresh_tokens IS 'Refresh Token 원본 (해시 저장)';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 해시. 원문 토큰은 DB에 저장하지 않는다 (보안 요구사항)';
COMMENT ON COLUMN refresh_tokens.family_id IS '로그인(Authorization Code Flow 최초 진입) 시점마다 새로 발급. 같은 기기/세션에서 Rotation된 토큰들은 같은 family_id를 공유하며, 재사용 감지 시 이 값으로 체인 전체를 한 번에 폐기한다';
