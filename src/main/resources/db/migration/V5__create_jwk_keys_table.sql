CREATE TABLE jwk_keys
(
    id                     BIGSERIAL PRIMARY KEY,
    key_id                 VARCHAR(100) NOT NULL, -- JWKS의 kid로 노출되는 값
    curve                  VARCHAR(20)  NOT NULL DEFAULT 'P-256',
    algorithm              VARCHAR(20)  NOT NULL DEFAULT 'ES256',
    encrypted_private_key  TEXT         NOT NULL, -- AES-256으로 암호화된 EC 개인키
    public_key             TEXT         NOT NULL, -- 공개키는 평문 저장 (민감정보 아님, JWKS로 어차피 노출됨)
    active                 BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at           TIMESTAMP,
    retired_at             TIMESTAMP,

    CONSTRAINT uq_jwk_keys_key_id UNIQUE (key_id)
);

CREATE INDEX idx_jwk_keys_active ON jwk_keys (active);

COMMENT ON TABLE jwk_keys IS 'EC(ES256) 키페어 관리 (운영환경 서명키 소스)';
COMMENT ON COLUMN jwk_keys.encrypted_private_key IS 'AES-256 암호화. 복호화 로직은 Phase3에서 JwkSourceConfig.databaseEcKey()에 연동';
