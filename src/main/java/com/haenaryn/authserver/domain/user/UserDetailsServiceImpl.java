package com.haenaryn.authserver.domain.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Spring Security의 로그인 폼(username/password 인증)이 사용하는 {@link UserDetailsService}
 * 구현체. username 자리에 {@code User.email}을 그대로 사용한다.
 *
 * <p>계정 잠금(Phase4, 로그인 실패 5회) 로직은 여기 반영돼 있다 — {@code User.accountLocked}를
 * {@link UserDetails#isAccountNonLocked()}에 그대로 매핑해두면, 잠금 처리 자체는 나중에
 * 만들 로그인 실패 카운터 서비스에서 {@code User.lockAccount()}만 호출해주면 되고
 * 이 클래스는 수정할 필요가 없다.</p>
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPasswordHash())
                .disabled(!user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .authorities("ROLE_USER")
                .build();
    }
}
