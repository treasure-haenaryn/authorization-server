package com.haenaryn.authserver.security;

import com.haenaryn.authserver.cache.RedisKeys;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 로그인 성공 시 해당 이메일의 로그인 실패 카운터(Redis)를 초기화한다 — 실패 이력이
 * 다음 로그인 시도에 이어지지 않도록. 리다이렉트 동작은 기본값(직전에 요청했던 URL,
 * 예: {@code /oauth2/authorize})을 그대로 유지하기 위해 부모 클래스를 상속한다.
 */
@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final RedisTemplate<String, String> redisTemplate;

    public LoginSuccessHandler(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws ServletException, IOException {
        redisTemplate.delete(RedisKeys.loginFail(authentication.getName()));
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
