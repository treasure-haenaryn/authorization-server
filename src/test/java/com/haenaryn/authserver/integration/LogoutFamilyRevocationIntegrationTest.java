package com.haenaryn.authserver.integration;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper;
import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper.TokenResponse;
import com.haenaryn.authserver.integration.support.PartmanPostgresImage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Postgres/Redis 컨테이너 + 전체 Spring 컨텍스트로 Authorization Code Flow를 처음부터 끝까지 재현해,
 * 로그아웃 이후 같은 refresh_token으로는 재발급 불가능을 확인한다.
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LogoutFamilyRevocationIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(PartmanPostgresImage.NAME)
            .withDatabaseName("authserver")
            .withUsername("authserver")
            .withPassword("authserver");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    private static final PasswordEncoder PASSWORD_ENCODER = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    private static final String CLIENT_ID = "logout-test-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String USER_EMAIL = "logout-flow@haenaryn.com";
    private static final String USER_PASSWORD = "password1234";

    @LocalServerPort
    private int port;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private UserRepository userRepository;

    private RestTemplate restTemplate;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        restTemplate = OAuth2AuthorizationCodeFlowHelper.newRestTemplate();
        baseUrl = "http://localhost:" + port;

        if (registeredClientRepository.findByClientId(CLIENT_ID) == null) {
            registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(CLIENT_ID)
                    .clientSecret(PASSWORD_ENCODER.encode(CLIENT_SECRET))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri(REDIRECT_URI)
                    .scope(OidcScopes.OPENID)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())
                    .build());
        }

        if (userRepository.findByEmail(USER_EMAIL).isEmpty()) {
            userRepository.save(User.builder()
                    .email(USER_EMAIL)
                    .passwordHash(PASSWORD_ENCODER.encode(USER_PASSWORD))
                    .name("Logout Flow Test")
                    .build());
        }
    }

    @Test
    void logout_revokes_the_entire_refresh_token_family_so_the_old_refresh_token_can_never_be_used_again() {
        TokenResponse tokens = OAuth2AuthorizationCodeFlowHelper.obtainTokens(
                restTemplate, baseUrl, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI,
                OidcScopes.OPENID, USER_EMAIL, USER_PASSWORD
        );

        // 로그아웃 -> access_token 블랙리스트 + family(refresh_token 체인) 전체 폐기
        HttpHeaders logoutHeaders = new HttpHeaders();
        logoutHeaders.setBearerAuth(tokens.accessToken());
        ResponseEntity<Void> logoutResponse = restTemplate.postForEntity(
                baseUrl + "/auth/logout", new HttpEntity<>(logoutHeaders), Void.class);
        assertThat(logoutResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        // 로그아웃 이후 같은 refresh_token으로 재발급 시도 -> family가 통째로 폐기됐으므로 거부돼야 함
        MultiValueMap<String, String> refreshForm = new LinkedMultiValueMap<>();
        refreshForm.add("grant_type", "refresh_token");
        refreshForm.add("refresh_token", tokens.refreshToken());

        ResponseEntity<String> refreshResponse = restTemplate.postForEntity(
                baseUrl + "/oauth2/token",
                new HttpEntity<>(refreshForm, OAuth2AuthorizationCodeFlowHelper.clientBasicAuthHeaders(CLIENT_ID, CLIENT_SECRET)),
                String.class);

        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refreshResponse.getBody()).contains("invalid_grant");
    }
}
