package com.haenaryn.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * OAuth2 클라이언트 등록 정보를 위한 {@link RegisteredClientRepository} 빈 설정.
 *
 * <p>커스텀 JPA 엔티티를 만들지 않고 Spring Authorization Server가 제공하는
 * {@link JdbcRegisteredClientRepository}를 사용.
 */
@Configuration
public class RegisteredClientRepositoryConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }
}
