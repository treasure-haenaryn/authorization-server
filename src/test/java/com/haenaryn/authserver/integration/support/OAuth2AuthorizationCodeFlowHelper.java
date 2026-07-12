package com.haenaryn.authserver.integration.support;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Authorization Code Flow(로그인 -> 인가 -> 토큰 교환)를 실제 HTTP 요청으로 재현하는
 * 통합 테스트 전용 헬퍼. 여러 통합 테스트 클래스(로그아웃 family 폐기, Redis 장애 대응)가
 * 동일한 흐름을 필요로 해서 공통으로 분리했다.
 */
public final class OAuth2AuthorizationCodeFlowHelper {

    private static final Pattern CSRF_INPUT_TAG_PATTERN = Pattern.compile("<input[^>]*name=\"_csrf\"[^>]*>");
    private static final Pattern VALUE_ATTRIBUTE_PATTERN = Pattern.compile("value=\"([^\"]*)\"");

    private OAuth2AuthorizationCodeFlowHelper() {
    }

    public static ClientHttpRequestFactory noRedirectRequestFactory() {
        return new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        };
    }

    /**
     * 리다이렉트 자동 추적을 꺼고, 4xx/5xx 응답에도 예외를 던지지 않는 {@link RestTemplate}을 만든다.
     * 기본 {@code RestTemplate}은 {@code DefaultResponseErrorHandler}가 4xx/5xx에 예외를 던져서,
     * "실패 응답을 받아서 그 상태코드/바디를 검증"하려는 통합 테스트의 의도(로그인 실패,
     * invalid_grant 검증 등)와 충돌한다. 상태코드 판단은 헬퍼/테스트 코드의 assert가 직접 맡는다.
     */
    public static RestTemplate newRestTemplate() {
        RestTemplate restTemplate = new RestTemplate(noRedirectRequestFactory());
        restTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }
        });
        return restTemplate;
    }

    /** 로그인 -> /oauth2/authorize -> /oauth2/token(authorization_code)까지 전부 수행해 토큰을 발급받는다. */
    public static TokenResponse obtainTokens(RestTemplate restTemplate, String baseUrl,
                                              String clientId, String clientSecret, String redirectUri,
                                              String scope, String username, String password) {
        // 1) 로그인 페이지에서 세션 쿠키 + CSRF 토큰 확보
        ResponseEntity<String> loginPage = restTemplate.getForEntity(baseUrl + "/login", String.class);
        String sessionCookie = extractCookie(loginPage.getHeaders(), "JSESSIONID");
        String csrfToken = extractCsrfToken(loginPage.getBody());
        assertThat(sessionCookie).as("로그인 페이지 세션 쿠키").isNotBlank();
        assertThat(csrfToken).as("로그인 페이지 CSRF 토큰").isNotBlank();

        // 2) 폼 로그인
        MultiValueMap<String, String> loginForm = new LinkedMultiValueMap<>();
        loginForm.add("username", username);
        loginForm.add("password", password);
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
        // Spring Security는 로그인 실패시에도 /login?error로 302 리다이렉트하므로, "3xx"만
        // 확인하면 로그인 실패를 놓칠 수 있다. 목적지가 실제 성공 리다이렉트("/login?error"가
        // 아니어야 함)인지까지 확인해야 다음 단계(인가 코드 발급)에서 진짜 원인을 바로 잡을 수 있다.
        assertThat(loginRedirectLocation == null || !loginRedirectLocation.toString().contains("error"))
                .as("로그인이 실제로 성공해야 함(실패 시 /login?error로 리다이렉트됨) — 리다이렉트 위치: " + loginRedirectLocation)
                .isTrue();

        String authenticatedCookie = extractCookie(loginResponse.getHeaders(), "JSESSIONID");
        String sessionForAuthorize = authenticatedCookie != null ? authenticatedCookie : sessionCookie;

        // 3) 인가 코드 발급 (client가 requireAuthorizationConsent=false라 동의 화면 없이 바로 리다이렉트)
        // PKCE(RFC 7636): Spring Authorization Server가 client_secret 유무와 무관하게
        // Authorization Code Flow에 code_challenge를 기본으로 요구하므로, 테스트도 실제 프로토콜에 맞게
        // code_verifier/code_challenge(S256)를 생성해서 함께 보낸다.
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = computeS256CodeChallenge(codeVerifier);

        String authorizeUrl = baseUrl + "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&scope=" + scope + "&redirect_uri=" + redirectUri + "&state=xyz"
                + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
        HttpHeaders authorizeHeaders = new HttpHeaders();
        authorizeHeaders.add(HttpHeaders.COOKIE, "JSESSIONID=" + sessionForAuthorize);

        ResponseEntity<Void> authorizeResponse = restTemplate.exchange(
                authorizeUrl, HttpMethod.GET, new HttpEntity<>(authorizeHeaders), Void.class);
        assertThat(authorizeResponse.getStatusCode().is3xxRedirection())
                .as("인가 코드 발급 시 리다이렉트(3xx)여야 함 — 응답: " + authorizeResponse.getStatusCode())
                .isTrue();

        URI redirectLocation = authorizeResponse.getHeaders().getLocation();
        assertThat(redirectLocation).as("인가 코드 리다이렉트 Location 헤더").isNotNull();
        String code = extractQueryParam(redirectLocation.toString(), "code");
        assertThat(code).as("인가 코드 — 리다이렉트 위치: " + redirectLocation).isNotBlank();

        // 4) 인가 코드 -> access_token/refresh_token 교환 (PKCE: code_verifier 함께 전달)
        MultiValueMap<String, String> tokenForm = new LinkedMultiValueMap<>();
        tokenForm.add("grant_type", "authorization_code");
        tokenForm.add("code", code);
        tokenForm.add("redirect_uri", redirectUri);
        tokenForm.add("code_verifier", codeVerifier);

        ResponseEntity<TokenResponse> tokenResponse = restTemplate.postForEntity(
                baseUrl + "/oauth2/token",
                new HttpEntity<>(tokenForm, clientBasicAuthHeaders(clientId, clientSecret)),
                TokenResponse.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getBody()).isNotNull();

        return tokenResponse.getBody();
    }

    public static String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public static String computeS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없음", e);
        }
    }

    public static HttpHeaders clientBasicAuthHeaders(String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String credentials = clientId + ":" + clientSecret;
        headers.add(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes()));
        return headers;
    }

    public static String extractCookie(HttpHeaders headers, String cookieName) {
        List<String> setCookieHeaders = headers.get(HttpHeaders.SET_COOKIE);
        if (setCookieHeaders == null) {
            return null;
        }
        for (String header : setCookieHeaders) {
            if (header.startsWith(cookieName + "=")) {
                String value = header.substring((cookieName + "=").length());
                int semicolon = value.indexOf(';');
                return semicolon >= 0 ? value.substring(0, semicolon) : value;
            }
        }
        return null;
    }

    public static String extractCsrfToken(String html) {
        if (html == null) {
            return null;
        }
        Matcher tagMatcher = CSRF_INPUT_TAG_PATTERN.matcher(html);
        if (!tagMatcher.find()) {
            return null;
        }
        Matcher valueMatcher = VALUE_ATTRIBUTE_PATTERN.matcher(tagMatcher.group());
        return valueMatcher.find() ? valueMatcher.group(1) : null;
    }

    private static String extractQueryParam(String url, String paramName) {
        Matcher matcher = Pattern.compile(paramName + "=([^&]+)").matcher(url);
        return matcher.find() ? matcher.group(1) : null;
    }

    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") Long expiresIn,
            String scope
    ) {
    }
}
