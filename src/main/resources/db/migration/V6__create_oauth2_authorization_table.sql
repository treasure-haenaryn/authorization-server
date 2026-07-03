-- Spring Authorization Server 공식 스키마 (JdbcOAuth2AuthorizationService가 기대하는 구조).
-- org.springframework.security.oauth2.server.authorization 패키지의
-- oauth2-authorization-schema.sql 기반. 라이브러리가 정한 구조라 원본 그대로 유지.
--
-- 주의: access_token_value / refresh_token_value 등은 원문이 그대로 저장된다
-- (JdbcOAuth2AuthorizationService는 WHERE ..._value = ? 형태로 값 매칭 조회를 하므로).
-- authorization_code / access_token / id_token은 이 방식을 그대로 쓰지만,
-- refresh_token은 "원문 미저장" 보안 요구사항이 있어 별도로 refresh_tokens 테이블
-- (해시 저장)에서 관리한다 — HybridOAuth2AuthorizationService 참고.
CREATE TABLE oauth2_authorization
(
    id                            VARCHAR(100)  NOT NULL,
    registered_client_id          VARCHAR(100)  NOT NULL,
    principal_name                VARCHAR(200)  NOT NULL,
    authorization_grant_type      VARCHAR(100)  NOT NULL,
    authorized_scopes             VARCHAR(1000) DEFAULT NULL,
    attributes                    TEXT          DEFAULT NULL,
    state                         VARCHAR(500)  DEFAULT NULL,

    authorization_code_value      TEXT          DEFAULT NULL,
    authorization_code_issued_at  TIMESTAMP     DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP     DEFAULT NULL,
    authorization_code_metadata   TEXT          DEFAULT NULL,

    access_token_value            TEXT          DEFAULT NULL,
    access_token_issued_at        TIMESTAMP     DEFAULT NULL,
    access_token_expires_at       TIMESTAMP     DEFAULT NULL,
    access_token_metadata         TEXT          DEFAULT NULL,
    access_token_type             VARCHAR(100)  DEFAULT NULL,
    access_token_scopes           VARCHAR(1000) DEFAULT NULL,

    oidc_id_token_value           TEXT          DEFAULT NULL,
    oidc_id_token_issued_at       TIMESTAMP     DEFAULT NULL,
    oidc_id_token_expires_at      TIMESTAMP     DEFAULT NULL,
    oidc_id_token_metadata        TEXT          DEFAULT NULL,

    refresh_token_value           TEXT          DEFAULT NULL,
    refresh_token_issued_at       TIMESTAMP     DEFAULT NULL,
    refresh_token_expires_at      TIMESTAMP     DEFAULT NULL,
    refresh_token_metadata        TEXT          DEFAULT NULL,

    user_code_value               TEXT          DEFAULT NULL,
    user_code_issued_at           TIMESTAMP     DEFAULT NULL,
    user_code_expires_at          TIMESTAMP     DEFAULT NULL,
    user_code_metadata            TEXT          DEFAULT NULL,

    device_code_value             TEXT          DEFAULT NULL,
    device_code_issued_at         TIMESTAMP     DEFAULT NULL,
    device_code_expires_at        TIMESTAMP     DEFAULT NULL,
    device_code_metadata          TEXT          DEFAULT NULL,

    PRIMARY KEY (id)
);

COMMENT ON TABLE oauth2_authorization IS 'OAuth2 인가/토큰 저장소 (Spring Authorization Server 공식 스키마). authorization_code/access_token/id_token 대상 — refresh_token은 refresh_tokens 테이블이 보안상 우선(해시)됨';
