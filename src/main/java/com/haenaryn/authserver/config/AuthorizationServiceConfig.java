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
 * <p>authorization_code/access_token/id_token은 공식 {@link JdbcOAuth2AuthorizationService}
 * (그리고 {@link com.haenaryn.authserver.config.RegisteredClientRepositoryConfig}에서 만든
 * {@code oauth2_registered_client} 테이블과 짝을 이루는 {@code oauth2_authorization}
 * 테이블)로 처리하고, refresh_token만 {@link HybridOAuth2AuthorizationService}가 가로채서
 * 우리 {@code refresh_tokens} 테이블(해시 저장 + family_id 재사용 감지)로 관리한다.
 *
 * <p>이 결정으로 얻는 것: 인가서버를 여러 인스턴스로 띄워도(로드밸런서 뒤, 롤링 배포 등)
 * authorization_code/access_token/id_token은 DB에 영속화되어 있어 정상 동작한다. 기존
 * 기본값인 {@code InMemoryOAuth2AuthorizationService}는 인스턴스별 메모리에만 있어서
 * 멀티 인스턴스 환경에서 근본적으로 깨지는 구조였다.</p>
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
