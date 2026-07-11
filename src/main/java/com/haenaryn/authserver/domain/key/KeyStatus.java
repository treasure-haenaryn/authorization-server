package com.haenaryn.authserver.domain.key;

/** 서명키 로테이션 상태. ACTIVE -> RETIRING -> RETIRED 단방향으로만 전이한다. */
public enum KeyStatus {
    /** 서명(발급)과 검증(JWKS 노출) 모두에 사용되는 현재 키. */
    ACTIVE,
    /** 새 키로 교체되어 더 이상 서명에는 쓰이지 않지만, grace period 동안 검증(JWKS 노출)에는 계속 쓰이는 키. */
    RETIRING,
    /** grace period가 지나 완전히 폐기된 키. JWKS에 노출되지 않으며 개인키 값은 wipe된다. */
    RETIRED
}
