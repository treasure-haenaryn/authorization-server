-- Spring Authorization Server 공식 스키마.
-- JdbcRegisteredClientRepository가 기대하는 컬럼 구조를 그대로 사용한다
-- (org.springframework.security.oauth2.server.authorization.client 패키지의
-- oauth2-registered-client-schema.sql 기반). 라이브러리가 정한 구조라
-- 프로젝트 PK 컨벤션(BIGSERIAL)을 적용하지 않고 원본 그대로 유지한다.
-- 자세한 배경은 요구사항 문서의 "기술 선택 근거" 참고.
CREATE TABLE oauth2_registered_client
(
    id                            VARCHAR(100)  NOT NULL,
    client_id                     VARCHAR(100)  NOT NULL,
    client_id_issued_at           TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_secret                 VARCHAR(200)  DEFAULT NULL,
    client_secret_expires_at      TIMESTAMP     DEFAULT NULL,
    client_name                   VARCHAR(200)  NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types     VARCHAR(1000) NOT NULL,
    redirect_uris                 VARCHAR(1000) DEFAULT NULL,
    post_logout_redirect_uris     VARCHAR(1000) DEFAULT NULL,
    scopes                        VARCHAR(1000) NOT NULL,
    client_settings                VARCHAR(2000) NOT NULL,
    token_settings                 VARCHAR(2000) NOT NULL,

    PRIMARY KEY (id)
);

COMMENT ON TABLE oauth2_registered_client IS 'OAuth2 클라이언트 등록 정보 (Spring Authorization Server 공식 스키마)';
