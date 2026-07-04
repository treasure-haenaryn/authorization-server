package com.haenaryn.authserver.config;

import com.haenaryn.authserver.domain.token.HybridOAuth2AuthorizationService;
import com.haenaryn.authserver.domain.token.RefreshTokenHistoryRepository;
import com.haenaryn.authserver.domain.token.RefreshTokenRepository;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * {@link OAuth2AuthorizationService} 빈 설정.
 *
 * <p>authorization_code/access_token/id_token은 {@link JdbcOAuth2AuthorizationService}에, refresh_token만
 * {@link HybridOAuth2AuthorizationService}가 가로채서 우리 {@code refresh_tokens} 테이블로 관리한다.</p>
 *
 */
@Configuration
public class AuthorizationServiceConfig {

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                             RegisteredClientRepository registeredClientRepository,
                                                             RefreshTokenRepository refreshTokenRepository,
                                                             RefreshTokenHistoryRepository refreshTokenHistoryRepository,
                                                             UserRepository userRepository) {
        JdbcOAuth2AuthorizationService jdbcDelegate =
                new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);

        return new HybridOAuth2AuthorizationService(
                jdbcDelegate, refreshTokenRepository, refreshTokenHistoryRepository,
                userRepository, registeredClientRepository
        );
    }
}
