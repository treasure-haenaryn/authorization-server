package com.haenaryn.authserver.domain.token;

/**
 * Refresh Token Rotation 이력의 이벤트 종류.
 */
public enum RefreshTokenEventType {
    ISSUED,
    ROTATED,
    REUSE_DETECTED,
    REVOKED
}
