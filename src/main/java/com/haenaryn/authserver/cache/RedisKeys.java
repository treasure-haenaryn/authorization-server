package com.haenaryn.authserver.cache;

import java.time.Duration;

/**
 * Redis 키 포맷과 TTL을 한 곳에서 관리한다. 문자열 조합을 서비스 코드에 흩어놓지 않기 위함.
 * 키 구조/TTL은 요구사항 문서의 Redis 키 구조 표를 그대로 따른다.
 */
public final class RedisKeys {

    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);
    public static final Duration BLACKLIST_TTL = Duration.ofMinutes(30);
    public static final Duration AUTH_CODE_TTL = Duration.ofMinutes(5);
    public static final Duration LOGIN_FAIL_TTL = Duration.ofHours(1);

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String BLACKLIST_PREFIX = "blacklist:";
    private static final String AUTH_CODE_PREFIX = "auth_code:";
    private static final String LOGIN_FAIL_PREFIX = "login_fail:";

    private RedisKeys() {
    }

    // TTL 7일
    public static String refreshToken(String tokenId) {
        return REFRESH_TOKEN_PREFIX + tokenId;
    }

    // 로그아웃된 Access Token 차단. TTL 30분 (Access Token 만료 시간과 동일)
    public static String blacklist(String jti) {
        return BLACKLIST_PREFIX + jti;
    }

    // Authorization Code Flow의 인가 코드. TTL 5분
    public static String authCode(String code) {
        return AUTH_CODE_PREFIX + code;
    }

    // 로그인 실패 카운트. TTL 1시간
    public static String loginFail(String email) {
        return LOGIN_FAIL_PREFIX + email;
    }
}
