package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * authorization_code/access_token/id_token 위임(delegate)과 refresh_token 자체 관리
 * (해시 저장 + family_id 재사용 감지)가 올바르게 나뉘어 동작하는지 검증.
 * 실제 JDBC/H2 없이 delegate와 리포지토리를 전부 Mockito로 대체한다.
 */
@ExtendWith(MockitoExtension.class)
class HybridOAuth2AuthorizationServiceTest {

    @Mock
    private OAuth2AuthorizationService delegate;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private RefreshTokenHistoryRepository refreshTokenHistoryRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    private HybridOAuth2AuthorizationService service;
    private RegisteredClient registeredClient;
    private User user;

    @BeforeEach
    void setUp() {
        service = new HybridOAuth2AuthorizationService(
                delegate, refreshTokenRepository, refreshTokenHistoryRepository,
                userRepository, registeredClientRepository
        );

        registeredClient = RegisteredClient.withId("internal-client-id")
                .clientId("oidc-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .build();

        user = User.builder().email("lee@haenaryn.com").passwordHash("hashed").build();

        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private OAuth2Authorization authorizationWithRefreshToken(String authorizationId, String rawRefreshTokenValue) {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                rawRefreshTokenValue, Instant.now(), Instant.now().plus(Duration.ofDays(7))
        );
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(authorizationId)
                .principalName("lee@haenaryn.com")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .refreshToken(refreshToken)
                .build();
    }

    @Test
    void save_records_new_refresh_token_with_family_id_equal_to_authorization_id() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        when(refreshTokenRepository.findAllByFamilyId(anyString())).thenReturn(List.of());
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);

        OAuth2Authorization authorization = authorizationWithRefreshToken("auth-1", "raw-refresh-token-v1");

        service.save(authorization);

        verify(delegate).save(authorization);

        RefreshTokenHistory capturedHistory = captureLastSavedHistory();
        assertThat(capturedHistory.getEventType()).isEqualTo(RefreshTokenEventType.ISSUED);
        assertThat(capturedHistory.getFamilyId()).isEqualTo("auth-1"); // authorization.getId()를 family_id로 재사용
    }

    @Test
    void save_called_again_with_new_refresh_token_marks_previous_as_rotated() {
        RefreshToken previous = RefreshToken.builder()
                .tokenHash(TokenHasher.sha256("raw-refresh-token-v1"))
                .familyId("auth-1")
                .user(user)
                .clientId("oidc-client")
                .expiresAt(java.time.LocalDateTime.now().plusDays(7))
                .build();

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        when(refreshTokenRepository.findAllByFamilyId("auth-1")).thenReturn(List.of(previous));
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);

        // 같은 authorization id(=family_id), 새 refresh token 값 -> rotation으로 취급돼야 함
        OAuth2Authorization rotated = authorizationWithRefreshToken("auth-1", "raw-refresh-token-v2");

        service.save(rotated);

        assertThat(previous.isRevoked()).isTrue();
        assertThat(previous.getRevokedBy()).isEqualTo("system-rotated");

        RefreshTokenHistory capturedHistory = captureLastSavedHistory();
        assertThat(capturedHistory.getEventType()).isEqualTo(RefreshTokenEventType.ROTATED);
    }

    @Test
    void findByToken_not_in_our_ledger_falls_through_to_delegate() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        OAuth2Authorization expected = authorizationWithRefreshToken("auth-2", "some-access-token-value");
        when(delegate.findByToken("some-access-token-value", null)).thenReturn(expected);

        OAuth2Authorization result = service.findByToken("some-access-token-value", null);

        assertThat(result).isSameAs(expected);
        verify(refreshTokenRepository, never()).bulkRevokeByFamilyId(anyString(), any(), anyString());
    }

    @Test
    void findByToken_with_already_revoked_token_triggers_reuse_detection() {
        RefreshToken revoked = RefreshToken.builder()
                .tokenHash(TokenHasher.sha256("stolen-token"))
                .familyId("auth-3")
                .user(user)
                .clientId("oidc-client")
                .expiresAt(java.time.LocalDateTime.now().plusDays(7))
                .build();
        revoked.revoke("system-rotated"); // 이미 한 번 교체되어 폐기된 상태

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(revoked));
        OAuth2Authorization compromised = authorizationWithRefreshToken("auth-3", "stolen-token");
        when(delegate.findByToken("stolen-token", null)).thenReturn(compromised);

        OAuth2Authorization result = service.findByToken("stolen-token", null);

        assertThat(result).isNull(); // 프레임워크가 invalid_grant로 해석하게 됨
        verify(refreshTokenRepository).bulkRevokeByFamilyId(eq("auth-3"), any(), eq("system-reuse-detected"));
        verify(delegate).remove(compromised); // 손상된 authorization도 JDBC에서 제거

        RefreshTokenHistory capturedHistory = captureLastSavedHistory();
        assertThat(capturedHistory.getEventType()).isEqualTo(RefreshTokenEventType.REUSE_DETECTED);
    }

    @Test
    void remove_revokes_entire_refresh_token_family() {
        OAuth2Authorization authorization = authorizationWithRefreshToken("auth-4", "raw-refresh-token-v1");

        service.remove(authorization);

        verify(delegate).remove(authorization);
        verify(refreshTokenRepository).bulkRevokeByFamilyId(eq("auth-4"), any(), eq("system-authorization-removed"));
    }

    private RefreshTokenHistory captureLastSavedHistory() {
        var captor = org.mockito.ArgumentCaptor.forClass(RefreshTokenHistory.class);
        verify(refreshTokenHistoryRepository).save(captor.capture());
        return captor.getValue();
    }
}
