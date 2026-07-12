package com.haenaryn.authserver.integration;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper;
import com.haenaryn.authserver.integration.support.PartmanPostgresImage;
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

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * /oauth2/authorize의 redirect_uri가 등록된 값과 완전 일치(exact string match)하지 않으면
 * 거부되고, 특히 그 미검증 redirect_uri로 리다이렉트되지 않는지(Open Redirect 방지)를
 * 검증한다. Spring Authorization Server 기본 검증기(OAuth2AuthorizationCodeRequestAuthenticationValidator)
 * 동작이라 이 프로젝트가 직접 구현한 로직은 없지만, 향후 라이브러리 버전업이나
 * authorizationEndpoint 커스터마이징으로 인해 무시되는것을 막기 위한 테스트
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RedirectUriValidationIntegrationTest {

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
    private static final String CLIENT_ID = "redirect-uri-test-client";
    private static final String CLIENT_SECRET = "secret";
    private static final String REGISTERED_REDIRECT_URI = "https://example.com/callback";
    private static final String USER_EMAIL = "redirect-uri-test@haenaryn.com";
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

        // 이 테스트의 목적은 redirect_uri exact-match 검증이라 클라이언트 인증 방식 자체는
        // 중요하지 않다. 원래 공개 클라이언트(NONE)로 만들었었는데, 로그인된 세션으로 인가 코드를
        // 실제로 발급받는 대조군 테스트에서만 원인 불명의 400이 나서(이 프로젝트의 다른 통합
        // 테스트들이 전부 검증된 CLIENT_SECRET_BASIC 패턴을 쓰는 것과 대조적), 동일하게 검증된
        // CLIENT_SECRET_BASIC로 맞췄다. PKCE(requireProofKey)는 계속 강제한다.
        if (registeredClientRepository.findByClientId(CLIENT_ID) == null) {
            registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(CLIENT_ID)
                    .clientSecret(PASSWORD_ENCODER.encode(CLIENT_SECRET))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri(REGISTERED_REDIRECT_URI)
                    .scope(OidcScopes.OPENID)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(true)
                            .build())
                    .build());
        }

        if (userRepository.findByEmail(USER_EMAIL).isEmpty()) {
            userRepository.save(User.builder()
                    .email(USER_EMAIL)
                    .passwordHash(PASSWORD_ENCODER.encode(USER_PASSWORD))
                    .name("Redirect URI Test")
                    .build());
        }
    }

    @Test
    void authorize_rejects_completely_different_domain_and_does_not_redirect_there() {
        assertRedirectUriRejectedWithoutOpenRedirect("https://evil.com/callback");
    }

    @Test
    void authorize_rejects_extra_path_appended_to_registered_uri_and_does_not_redirect_there() {
        // prefix 매칭이 허용된다면 등록된 URI 뒤에 임의 경로를 붙여 우회할 수 있어야 하는데,
        // exact match라면 이것도 그냥 다른 문자열이라 거부돼야 한다.
        assertRedirectUriRejectedWithoutOpenRedirect(REGISTERED_REDIRECT_URI + "/../evil");
    }

    @Test
    void authorize_rejects_subdomain_lookalike_and_does_not_redirect_there() {
        // example.com을 등록해놓고 example.com.evil.com처럼 등록 도메인을 "포함"만 하는
        // 서브도메인/룩얼라이크 우회 시도.
        assertRedirectUriRejectedWithoutOpenRedirect("https://example.com.evil.com/callback");
    }

    @Test
    void authorize_rejects_query_parameter_appended_to_registered_uri_and_does_not_redirect_there() {
        // 등록된 URI에 쿼리 파라미터만 추가해서 우회를 시도 — 파라미터 변조를 통한
        // open redirect 시나리오.
        assertRedirectUriRejectedWithoutOpenRedirect(REGISTERED_REDIRECT_URI + "?next=https://evil.com");
    }

    @Test
    void authorize_accepts_the_exact_registered_redirect_uri() {
        // 대조군: 등록된 값 그대로 보내면 정상적으로 인가 코드 발급 리다이렉트가 나가야 한다.
        // (다른 테스트들이 "전부 거부됨"만 확인하면, 검증기가 모든 요청을 무조건 막는
        // 버그가 있어도 통과해버릴 수 있어 이 대조군이 필요하다)
        // client_id/redirect_uri 검증은 인증 여부와 무관하게 통과하지만, 실제로 인가 코드가
        // 발급되려면(=대조군이 진짜로 성공을 확인하려면) 로그인된 세션이 있어야 한다.
        String sessionCookie = loginAndGetSessionCookie();
        ResponseEntity<String> response = callAuthorize(REGISTERED_REDIRECT_URI, sessionCookie);

        assertThat(response.getStatusCode().is3xxRedirection())
                .as("정상 등록된 redirect_uri는 인가 코드 발급 리다이렉트(3xx)여야 함 — 실제 응답: " + response.getStatusCode()
                        + ", 바디: " + response.getBody()
                        + ", 헤더: " + response.getHeaders())
                .isTrue();
        URI location = response.getHeaders().getLocation();
        assertThat(location).as("리다이렉트 Location 헤더").isNotNull();
        assertThat(location.toString())
                .as("등록된 redirect_uri로, 인가 코드(code=)와 함께 리다이렉트돼야 함 — 실제 Location: " + location)
                .startsWith(REGISTERED_REDIRECT_URI)
                .contains("code=");
    }

    private void assertRedirectUriRejectedWithoutOpenRedirect(String maliciousRedirectUri) {
        ResponseEntity<String> response = callAuthorize(maliciousRedirectUri, null);

        // 핵심 보안 불변조건: 응답이 리다이렉트라면, 절대로 공격자가 보낸(미검증) redirect_uri로
        // 향해서는 안 된다 (Open Redirect 방지). Spring Authorization Server 기본 동작은 아예
        // 그 URI로 리다이렉트하지 않고 에러를 직접 렌더링하지만, 상태 코드/바디 형식은 버전마다
        // 달라질 수 있으므로 이 불변조건 하나만 엄격하게 검증한다.
        URI location = response.getHeaders().getLocation();
        if (location != null) {
            assertThat(location.toString())
                    .as("등록되지 않은 redirect_uri(" + maliciousRedirectUri + ")로 리다이렉트되면 안 됨 — 실제 Location: " + location)
                    .doesNotStartWith(maliciousRedirectUri);
        }
        assertThat(response.getStatusCode())
                .as("등록되지 않은 redirect_uri로 인가 코드가 정상 발급되면 안 됨 — 실제 응답: " + response.getStatusCode())
                .isNotEqualTo(HttpStatus.OK);
    }

    /**
     * client_id/redirect_uri 자체의 유효성은 인증 확인보다 먼저 검사되므로(이 프로젝트의
     * 실제 동작으로 확인됨), 거부 케이스들은 세션 쿠키 없이(null) 익명으로 호출해도 충분하다.
     * 다만 정상 케이스(대조군)는 인가 코드가 실제로 발급되는지까지 확인해야 하므로 로그인된
     * 세션 쿠키가 필요하다.
     */
    private ResponseEntity<String> callAuthorize(String redirectUri, String sessionCookie) {
        String codeVerifier = OAuth2AuthorizationCodeFlowHelper.generateCodeVerifier();
        String codeChallenge = OAuth2AuthorizationCodeFlowHelper.computeS256CodeChallenge(codeVerifier);

        // 이 프로젝트의 다른 통합 테스트(OAuth2AuthorizationCodeFlowHelper.obtainTokens)는
        // redirect_uri를 URL 인코딩하지 않고 그대로 붙여서 쓰고, 그 방식으로 실제 인가 코드
        // 발급까지 검증된 상태다. "?next=..."처럼 예약 문자가 섞인 악성 케이스만 인코딩이
        // 필요해서, 그런 경우에만 인코딩하고 나머지는 검증된 방식과 동일하게 그대로 보낸다.
        String redirectUriParam = needsEncoding(redirectUri)
                ? URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                : redirectUri;

        String authorizeUrl = baseUrl + "/oauth2/authorize"
                + "?response_type=code"
                + "&client_id=" + CLIENT_ID
                + "&scope=" + OidcScopes.OPENID
                + "&redirect_uri=" + redirectUriParam
                + "&state=xyz"
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256";

        if (sessionCookie == null) {
            return restTemplate.getForEntity(authorizeUrl, String.class);
        }

        HttpHeaders authorizeHeaders = new HttpHeaders();
        authorizeHeaders.add(HttpHeaders.COOKIE, "JSESSIONID=" + sessionCookie);
        return restTemplate.exchange(
                authorizeUrl, HttpMethod.GET, new HttpEntity<>(authorizeHeaders), String.class);
    }

    /** "&"/"="/"?"처럼 쿼리 문자열 구조를 깨는 예약 문자가 값 안에 섞여 있을 때만 인코딩이 필요하다. */
    private boolean needsEncoding(String redirectUri) {
        return redirectUri.indexOf('?') >= 0 || redirectUri.indexOf('&') >= 0 || redirectUri.indexOf('=') >= 0;
    }

    /** 로그인 페이지에서 CSRF 토큰을 받아 폼 로그인을 수행하고, 인증된 세션 쿠키를 반환한다. */
    private String loginAndGetSessionCookie() {
        ResponseEntity<String> loginPage = restTemplate.getForEntity(baseUrl + "/login", String.class);
        String sessionCookie = OAuth2AuthorizationCodeFlowHelper.extractCookie(loginPage.getHeaders(), "JSESSIONID");
        String csrfToken = OAuth2AuthorizationCodeFlowHelper.extractCsrfToken(loginPage.getBody());
        assertThat(sessionCookie).as("로그인 페이지 세션 쿠키").isNotBlank();
        assertThat(csrfToken).as("로그인 페이지 CSRF 토큰").isNotBlank();

        MultiValueMap<String, String> loginForm = new LinkedMultiValueMap<>();
        loginForm.add("username", USER_EMAIL);
        loginForm.add("password", USER_PASSWORD);
        loginForm.add("_csrf", csrfToken);

        HttpHeaders loginHeaders = new HttpHeaders();
        loginHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginHeaders.add(HttpHeaders.COOKIE, "JSESSIONID=" + sessionCookie);

        ResponseEntity<Void> loginResponse = restTemplate.postForEntity(
                baseUrl + "/login", new HttpEntity<>(loginForm, loginHeaders), Void.class);
        assertThat(loginResponse.getStatusCode().is3xxRedirection())
                .as("로그인 성공 시 리다이렉트(3xx)여야 함 — 응답: " + loginResponse.getStatusCode())
                .isTrue();
        URI loginRedirectLocation = loginResponse.getHeaders().getLocation();
        assertThat(loginRedirectLocation == null || !loginRedirectLocation.toString().contains("error"))
                .as("로그인이 실제로 성공해야 함(실패 시 /login?error로 리다이렉트됨) — 리다이렉트 위치: " + loginRedirectLocation)
                .isTrue();

        String authenticatedCookie = OAuth2AuthorizationCodeFlowHelper.extractCookie(loginResponse.getHeaders(), "JSESSIONID");
        return authenticatedCookie != null ? authenticatedCookie : sessionCookie;
    }
}
