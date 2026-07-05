package com.haenaryn.authserver.domain.user;

import com.haenaryn.authserver.config.AuthServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * 로그인 폼 인증이 사용하는 UserDetailsService 구현체 검증.
 * 계정 잠금 매핑과, 잠금 윈도우 경과 시 자동 잠금 해제(unlockAccount)가 핵심 검증 대상.
 */
@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    private UserDetailsServiceImpl service;

    @BeforeEach
    void setUp() {
        AuthServerProperties properties = new AuthServerProperties(
                null, null, new AuthServerProperties.Security(5, 1, false), null, null
        );
        service = new UserDetailsServiceImpl(userRepository, properties);
    }

    private User newUser() {
        return User.builder().email("lee@haenaryn.com").passwordHash("hashed-password").build();
    }

    @Test
    void loadUserByUsername_maps_user_fields_to_user_details() {
        User user = newUser();
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        UserDetails details = service.loadUserByUsername("lee@haenaryn.com");

        assertThat(details.getUsername()).isEqualTo("lee@haenaryn.com");
        assertThat(details.getPassword()).isEqualTo("hashed-password");
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
    }

    @Test
    void loadUserByUsername_throws_when_user_not_found() {
        when(userRepository.findByEmail("ghost@haenaryn.com")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("ghost@haenaryn.com"));
    }

    @Test
    void loadUserByUsername_reflects_locked_account_as_non_locked_false() {
        User user = newUser();
        user.lockAccount();
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        UserDetails details = service.loadUserByUsername("lee@haenaryn.com");

        assertThat(details.isAccountNonLocked()).isFalse();
    }

    @Test
    void loadUserByUsername_auto_unlocks_account_once_lock_window_has_elapsed() {
        User user = newUser();
        user.lockAccount();
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));

        AuthServerProperties zeroWindowProperties = new AuthServerProperties(
                null, null, new AuthServerProperties.Security(5, 0, false), null, null
        );
        UserDetailsServiceImpl serviceWithZeroWindow = new UserDetailsServiceImpl(userRepository, zeroWindowProperties);

        UserDetails details = serviceWithZeroWindow.loadUserByUsername("lee@haenaryn.com");

        assertThat(user.isAccountLocked()).isFalse();
        assertThat(details.isAccountNonLocked()).isTrue();
    }
}
