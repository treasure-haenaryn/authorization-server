package com.haenaryn.authserver.integration;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper;
import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Redis 컨테이너를 실제로 강제 종료(stop)한 상태에서, fail-open 원칙
 * (로그인 잠금, Rate Limiting, Access Token 블랙리스트)이 HTTP 레벨에서 실제로 지켜지는지
 * 검증한다.
 *
 * <p> "Redis가 진짜로 죽었을 때 애플리케이션이 500 에러 없이 정상 응답하는가"를 실제 컨테이너로
 * 검증하는 것이 목적이다.</p>
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RedisFailoverIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16"))
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
    private static final String CLIENT_ID = "redis-failover-test-client";
    private static final String M2M_CLIENT_ID = "redis-failover-m2m-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String USER_EMAIL = "redis-failover@haenaryn.com";
    private static final String USER_PASSWORD = "password1234";
    private static final String LOCKOUT_TEST_EMAIL = "redis-failover-lockout@haenaryn.com";

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

        if (registeredClientRepository.findByClientId(M2M_CLIENT_ID) == null) {
            registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(M2M_CLIENT_ID)
                    .clientSecret(PASSWORD_ENCODER.encode(CLIENT_SECRET))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("test:read")
                    .build());
        }

        if (userRepository.findByEmail(USER_EMAIL).isEmpty()) {
            userRepository.save(User.builder()
                    .email(USER_EMAIL)
                    .passwordHash(PASSWORD_ENCODER.encode(USER_PASSWORD))
                    .name("Redis Failover Test")
                    .build());
        }

        if (userRepository.findByEmail(LOCKOUT_TEST_EMAIL).isEmpty()) {
            userRepository.save(User.builder()
                    .email(LOCKOUT_TEST_EMAIL)
                    .passwordHash(PASSWORD_ENCODER.encode(USER_PASSWORD))
                    .name("Redis Failover Lockout Test")
                    .build());
        }
    }

    @Test
    void redis_outage_fails_open_across_blacklist_login_lockout_and_rate_limiting() {
        // 0) Redis가 살아있는 상태에서 정상적으로 토큰을 발급받아 둔다 (이후 블랙리스트 체크 대상).
        TokenResponse tokens = OAuth2AuthorizationCodeFlowHelper.obtainTokens(
                restTemplate, baseUrl, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI,
                OidcScopes.OPENID, USER_EMAIL, USER_PASSWORD
        );

        HttpHeaders bearerHeaders = new HttpHeaders();
        bearerHeaders.setBearerAuth(tokens.accessToken());
        ResponseEntity<String> userInfoBeforeOutage = restTemplate.exchange(
                baseUrl + "/userinfo", HttpMethod.GET, new HttpEntity<>(bearerHeaders), String.class);
        assertThat(userInfoBeforeOutage.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 1) Redis를 실제로 강제 종료한다.
        redis.stop();

        // 2) 블랙리스트 체크(Redis 조회) 실패 -> fail-open으로 여전히 200이어야 함.
        ResponseEntity<String> userInfoAfterOutage = restTemplate.exchange(
                baseUrl + "/userinfo", HttpMethod.GET, new HttpEntity<>(bearerHeaders), String.class);
        assertThat(userInfoAfterOutage.getStatusCode())
                .as("Redis 장애 시에도 블랙리스트 체크는 fail-open으로 통과해야 함")
                .isEqualTo(HttpStatus.OK);

        // 3) Rate Limiting(bucket4j 전용 Redis 연결)도 조회 실패 -> fail-open으로 통과해 200이어야 함.
        MultiValueMap<String, String> clientCredentialsForm = new LinkedMultiValueMap<>();
        clientCredentialsForm.add("grant_type", "client_credentials");
        ResponseEntity<String> tokenEndpointResponse = restTemplate.postForEntity(
                baseUrl + "/oauth2/token",
                new HttpEntity<>(clientCredentialsForm,
                        OAuth2AuthorizationCodeFlowHelper.clientBasicAuthHeaders(M2M_CLIENT_ID, CLIENT_SECRET)),
                String.class);
        assertThat(tokenEndpointResponse.getStatusCode())
                .as("Redis 장애 시에도 Rate Limiting은 fail-open으로 통과해 정상적으로 토큰이 발급돼야 함")
                .isEqualTo(HttpStatus.OK);

        // 4) 로그인 실패 카운트(Redis) 조회 실패 -> PostgreSQL 폴백 경로로 전환되어, 에러(5xx) 없이
        //    여전히 "/login?error"로 리다이렉트되고, 임계값(5회) 도달 시 DB 폴백으로 계정이 잠겨야 한다.
        int threshold = 5;
        for (int attempt = 1; attempt <= threshold; attempt++) {
            ResponseEntity<Void> failedLoginResponse = attemptLogin(LOCKOUT_TEST_EMAIL, "wrong-password");
            assertThat(failedLoginResponse.getStatusCode().is3xxRedirection())
                    .as("Redis 장애 중에도 로그인 실패 처리 자체는 500 없이 리다이렉트로 끝나야 함 (시도 " + attempt + ")")
                    .isTrue();
        }

        Optional<User> lockedOutUser = userRepository.findByEmail(LOCKOUT_TEST_EMAIL);
        assertThat(lockedOutUser).isPresent();
        assertThat(lockedOutUser.get().isAccountLocked())
                .as("Redis 장애 시 PostgreSQL 폴백 경로로 계정 잠금이 계속 동작해야 함")
                .isTrue();
    }

    private ResponseEntity<Void> attemptLogin(String email, String password) {
        ResponseEntity<String> loginPage = restTemplate.getForEntity(baseUrl + "/login", String.class);
        String sessionCookie = OAuth2AuthorizationCodeFlowHelper.extractCookie(loginPage.getHeaders(), "JSESSIONID");
        String csrfToken = extractCsrfTokenOrFail(loginPage.getBody());

        MultiValueMap<String, String> loginForm = new LinkedMultiValueMap<>();
        loginForm.add("username", email);
        loginForm.add("password", password);
        loginForm.add("_csrf", csrfToken);

        HttpHeaders loginHeaders = new HttpHeaders();
        loginHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginHeaders.add(HttpHeaders.COOKIE, "JSESSIONID=" + sessionCookie);

        return restTemplate.postForEntity(baseUrl + "/login", new HttpEntity<>(loginForm, loginHeaders), Void.class);
    }

    private String extractCsrfTokenOrFail(String html) {
        String token = OAuth2AuthorizationCodeFlowHelper.extractCsrfToken(html);
        assertThat(token).as("로그인 페이지에서 CSRF 토큰을 찾을 수 없음").isNotBlank();
        return token;
    }
}
