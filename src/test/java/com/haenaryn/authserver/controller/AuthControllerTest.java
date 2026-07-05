package com.haenaryn.authserver.controller;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * JWT 기반 로그아웃 엔드포인트 검증: jti 추출 -> 블랙리스트 등록 -> authorization 제거 -> 감사 로그.
 * Redis 장애 시에도 로그아웃 자체는 실패하지 않아야 한다(fail-open).
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private OAuth2AuthorizationService authorizationService;
    @Mock
    private RedisTemplate<String, String> redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private AuditLogService auditLogService;

    private AuthController controller;
    private RegisteredClient registeredClient;

    @BeforeEach
    void setUp() {
        controller = new AuthController(authorizationService, redisTemplate, auditLogService);
        registeredClient = RegisteredClient.withId("internal-client-id")
                .clientId("oidc-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .build();
    }

    private OAuth2Authorization authorizationWithAccessTokenClaims(Map<String, Object> claims) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "access-token-value",
                Instant.now(), Instant.now().plusSeconds(1800)
        );
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("lee@haenaryn.com")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .build();
    }

    @Test
    void logout_returns_bad_request_when_authorization_header_is_missing() {
        ResponseEntity<Void> response = controller.logout(null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(authorizationService, redisTemplate, auditLogService);
    }

    @Test
    void logout_returns_bad_request_when_header_is_not_bearer() {
        ResponseEntity<Void> response = controller.logout("Basic abcdef");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(authorizationService, redisTemplate, auditLogService);
    }

    @Test
    void logout_returns_no_content_when_token_is_unknown() {
        when(authorizationService.findByToken("unknown-token", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(null);

        ResponseEntity<Void> response = controller.logout("Bearer unknown-token");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verifyNoInteractions(redisTemplate, auditLogService);
    }

    @Test
    void logout_blacklists_jti_removes_authorization_and_records_audit_log() {
        OAuth2Authorization authorization = authorizationWithAccessTokenClaims(Map.of("jti", "jti-abc"));
        when(authorizationService.findByToken("access-token-value", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        ResponseEntity<Void> response = controller.logout("Bearer access-token-value");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(valueOperations).set(RedisKeys.blacklist("jti-abc"), "1", RedisKeys.BLACKLIST_TTL);
        verify(authorizationService).remove(authorization);
        verify(auditLogService).record(AuditEventType.LOGOUT, "lee@haenaryn.com", null);
    }

    @Test
    void logout_still_removes_authorization_when_jti_claim_is_missing() {
        OAuth2Authorization authorization = authorizationWithAccessTokenClaims(Map.of("sub", "lee@haenaryn.com"));
        when(authorizationService.findByToken("access-token-value", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization);

        ResponseEntity<Void> response = controller.logout("Bearer access-token-value");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verifyNoInteractions(redisTemplate);
        verify(authorizationService).remove(authorization);
    }

    @Test
    void logout_fails_open_and_still_succeeds_when_redis_throws() {
        OAuth2Authorization authorization = authorizationWithAccessTokenClaims(Map.of("jti", "jti-abc"));
        when(authorizationService.findByToken("access-token-value", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(authorization);
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis connection refused"));

        ResponseEntity<Void> response = controller.logout("Bearer access-token-value");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(authorizationService).remove(authorization);
        verify(auditLogService).record(AuditEventType.LOGOUT, "lee@haenaryn.com", null);
    }
}
