package com.haenaryn.authserver.domain.user;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void save_and_findByEmail() {
        User user = User.builder()
                .email("lee@haenaryn.com")
                .passwordHash("hashed-password")
                .name("Lee")
                .build();

        userRepository.save(user);

        Optional<User> found = userRepository.findByEmail("lee@haenaryn.com");

        assertThat(found).isPresent();
        assertThat(found.get().getName()).isEqualTo("Lee");
        assertThat(found.get().isEnabled()).isTrue();
        assertThat(found.get().isAccountLocked()).isFalse();
        assertThat(found.get().getCreatedAt()).isNotNull();
    }

    @Test
    void existsByEmail_returns_false_when_not_found() {
        assertThat(userRepository.existsByEmail("nobody@haenaryn.com")).isFalse();
    }
}
