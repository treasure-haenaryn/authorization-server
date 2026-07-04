package com.haenaryn.authserver.domain.user;

import com.haenaryn.authserver.config.AuthServerProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Spring Security의 로그인 폼(username/password 인증)이 사용하는 {@link UserDetailsService}
 * 구현체. username 자리에 {@code User.email}을 그대로 사용한다.
 *
 * <p>계정 잠금(Phase4, 로그인 실패 {@code loginFailLockThreshold}회) 상태를
 * {@link UserDetails#isAccountNonLocked()}에 매핑한다. 잠금 후
 * {@code loginFailWindowHours}가 지나면 자동으로 잠금을 풀어준다
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final AuthServerProperties properties;

    public UserDetailsServiceImpl(UserRepository userRepository, AuthServerProperties properties) {
        this.userRepository = userRepository;
        this.properties = properties;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));

        if (user.isLockExpired(properties.security().loginFailWindowHours())) {
            user.unlockAccount();
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPasswordHash())
                .disabled(!user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .authorities("ROLE_USER")
                .build();
    }
}
