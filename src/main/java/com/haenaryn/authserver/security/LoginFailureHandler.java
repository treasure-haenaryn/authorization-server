package com.haenaryn.authserver.security;

import com.haenaryn.authserver.domain.user.LoginLockoutService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 로그인 실패 시 요청에서 username을 추출해 {@link LoginLockoutService}에 위임.
 */
@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final LoginLockoutService loginLockoutService;

    public LoginFailureHandler(LoginLockoutService loginLockoutService) {
        super("/login?error");
        this.loginLockoutService = loginLockoutService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationException exception) throws IOException, ServletException {
        String email = request.getParameter("username");
        if (email != null && !email.isBlank()) {
            loginLockoutService.registerFailure(email);
        }
        super.onAuthenticationFailure(request, response, exception);
    }
}
