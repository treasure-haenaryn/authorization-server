package com.haenaryn.authserver.domain.token;

/**
 * 이미 폐기(rotated 또는 revoked)된 refresh token이 다시 사용됐을 때 — 토큰 탈취
 * 의심 시나리오. 이 예외가 던져진 시점엔 이미 {@code familyId} 체인 전체가
 * {@link RefreshTokenRepository#bulkRevokeByFamilyId}로 폐기된 뒤다.
 */
public class RefreshTokenReuseDetectedException extends RuntimeException {

    private final String familyId;

    public RefreshTokenReuseDetectedException(String familyId) {
        super("Refresh token 재사용이 감지되어 family_id=" + familyId + " 체인 전체를 폐기했습니다.");
        this.familyId = familyId;
    }

    public String getFamilyId() {
        return familyId;
    }
}
