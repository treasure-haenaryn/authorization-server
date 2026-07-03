package com.haenaryn.authserver.domain.token;

/**
 * 발급 직후 클라이언트에게 내려줄 원문 토큰과, DB에 저장된 엔티티(해시만 담고 있음)를
 * 함께 묶은 값. 원문은 이 응답 객체를 벗어나면 다시는 얻을 수 없다 — DB에는 해시만
 * 남기 때문.
 */
public record IssuedRefreshToken(String rawToken, RefreshToken entity) {
}
