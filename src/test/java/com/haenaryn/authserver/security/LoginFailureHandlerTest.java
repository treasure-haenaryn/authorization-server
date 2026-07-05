package com.haenaryn.authserver.security;

import com.haenaryn.authserver.domain.user.LoginLockoutService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LoginFailureHandlerTest {

    @Mock
    private LoginLockoutService loginLockoutService;

    private LoginFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new LoginFailureHandler(loginLockoutService);
    }

    @Test
    void onAuthenticationFailure_extracts_username_and_delegates_to_lockout_service() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("username", "lee@haenaryn.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(loginLockoutService).registerFailure("lee@haenaryn.com");
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error");
    }

    @Test
    void onAuthenticationFailure_skips_delegation_when_username_is_blank() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(loginLockoutService, never()).registerFailure(org.mockito.ArgumentMatchers.anyString());
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error");
    }
}
