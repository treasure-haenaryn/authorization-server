-- occurred_at 기준 월별 RANGE 파티션 테이블로 생성한다.
-- 파티션 키(occurred_at)가 PK에 포함돼야 하는 PostgreSQL 제약 때문에 PK는 (id, occurred_at) 복합키다.
-- 실제 파티션 생성/보존 기간 관리는 V11의 pg_partman 설정이 담당한다.
CREATE TABLE refresh_token_histories
(
    id                BIGSERIAL,
    user_id           BIGINT      NOT NULL REFERENCES users (id),
    family_id         VARCHAR(36) NOT NULL,                       -- refresh_tokens.family_id와 동일한 값. 체인 단위로 이력을 바로 조회하기 위해 비정규화
    previous_token_id BIGINT      REFERENCES refresh_tokens (id), -- 최초 발급이면 NULL. 상세 감사용 (재사용 감지 시 폐기 로직은 family_id로 처리하므로 이 링크에 의존하지 않음)
    new_token_id      BIGINT      REFERENCES refresh_tokens (id), -- 폐기/재사용감지면 NULL
    event_type        VARCHAR(30) NOT NULL,                       -- ISSUED / ROTATED / REUSE_DETECTED / REVOKED
    ip_address        VARCHAR(45),
    device_info       VARCHAR(255),
    occurred_at       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX idx_refresh_token_histories_user_id ON refresh_token_histories (user_id);
CREATE INDEX idx_refresh_token_histories_event_type ON refresh_token_histories (event_type);
CREATE INDEX idx_refresh_token_histories_family_id ON refresh_token_histories (family_id);
CREATE INDEX idx_refresh_token_histories_occurred_at ON refresh_token_histories (occurred_at);

COMMENT ON TABLE refresh_token_histories IS 'Refresh Token Rotation 이력 (occurred_at 기준 월별 RANGE 파티션, 파티션 생성/정리는 pg_partman이 관리)';
COMMENT ON COLUMN refresh_token_histories.event_type IS 'ISSUED(최초발급) / ROTATED(정상교체) / REUSE_DETECTED(재사용감지) / REVOKED(강제폐기)';
COMMENT ON COLUMN refresh_token_histories.family_id IS '체인 단위(로그인 세션) 이력 조회용. 실제 무효화 로직의 기준값은 refresh_tokens.family_id이며, previous/new_token_id는 상세 감사 기록 목적';
