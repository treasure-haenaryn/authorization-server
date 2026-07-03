package com.haenaryn.authserver.domain.token;

/**
 * Refresh Token Rotation 이력의 이벤트 종류.
 * Phase3의 Rotation 로직(재사용 감지 포함)이 이 값을 채워 refresh_token_histories에 기록한다.
 */
public enum RefreshTokenEventType {
    ISSUED,
    ROTATED,
    REUSE_DETECTED,
    REVOKED
}
