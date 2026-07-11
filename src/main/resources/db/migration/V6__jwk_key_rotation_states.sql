-- kid 다중 노출 기반 서명키 로테이션 지원 (ACTIVE/RETIRING/RETIRED 3단계). 설계 근거: Obsidian QA #16

ALTER TABLE jwk_keys
    ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';

ALTER TABLE jwk_keys
    ADD CONSTRAINT chk_jwk_keys_status CHECK (status IN ('ACTIVE', 'RETIRING', 'RETIRED'));

-- RETIRING -> RETIRED 전환 예정 시각
ALTER TABLE jwk_keys
    ADD COLUMN grace_expires_at TIMESTAMP;

-- RETIRED 전환 시 null로 wipe되므로 NOT NULL 완화
ALTER TABLE jwk_keys
    ALTER COLUMN encrypted_private_key DROP NOT NULL;

-- 기존 데이터 이관: active=true -> ACTIVE, active=false -> RETIRED
UPDATE jwk_keys
SET status = CASE WHEN active THEN 'ACTIVE' ELSE 'RETIRED' END;

DROP INDEX IF EXISTS idx_jwk_keys_active;

ALTER TABLE jwk_keys
    DROP COLUMN active;

CREATE INDEX idx_jwk_keys_status ON jwk_keys (status);

-- ACTIVE는 동시에 최대 1개만 존재 (부분 유니크 인덱스)
CREATE UNIQUE INDEX uq_jwk_keys_single_active ON jwk_keys ((true)) WHERE status = 'ACTIVE';

COMMENT ON COLUMN jwk_keys.status IS 'ACTIVE: 서명+검증, RETIRING: 검증만(grace), RETIRED: 미노출';
COMMENT ON COLUMN jwk_keys.grace_expires_at IS 'RETIRING -> RETIRED 전환 예정 시각';
