CREATE TABLE users
(
    id             BIGSERIAL PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    name           VARCHAR(100),
    enabled        BOOLEAN      NOT NULL DEFAULT TRUE,
    account_locked BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_users_email UNIQUE (email)
);

COMMENT ON TABLE users IS '회원 정보';
COMMENT ON COLUMN users.account_locked IS '로그인 실패 5회 초과 시 잠금 (Phase4 보안 요구사항)';
