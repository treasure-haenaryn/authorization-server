package com.haenaryn.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * bcrypt 기반 위임 인코더. {@code createDelegatingPasswordEncoder()}는 인코딩된 값 앞에
 * {@code {bcrypt}} 같은 접두어를 붙여 저장해, 향후 알고리즘을 교체(bcrypt -> argon2 등)해도
 * 기존 저장된 값과 새 값을 한 컬럼에서 함께 검증할 수 있게 해준다.
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
