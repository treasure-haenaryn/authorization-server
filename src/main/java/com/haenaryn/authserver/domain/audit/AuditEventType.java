package com.haenaryn.authserver.domain.audit;

/**
 * 감사(Audit) 대상 이벤트 종류. "누가/언제/무엇을" 조회가 필요한 보안 이벤트만 포함한다.
 */
public enum AuditEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ACCOUNT_LOCKED,
    LOGOUT,
    REFRESH_TOKEN_ISSUED,
    REFRESH_TOKEN_ROTATED,
    REFRESH_TOKEN_REUSE_DETECTED,
    REFRESH_TOKEN_REVOKED,
    SIGNING_KEY_ROTATED,
    SIGNING_KEY_RETIRED
}
