package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.audit.AuditLogService;
import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
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
    @Mock
    private AuditLogService auditLogService;

    private HybridOAuth2AuthorizationService service;
    private RegisteredClient registeredClient;
    private User user;

    @BeforeEach
    void setUp() {
        service = new HybridOAuth2AuthorizationService(
                delegate, refreshTokenRepository, refreshTokenHistoryRepository,
                userRepository, registeredClientRepository, auditLogService
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

    /** insertIfAbsentReturningId 성공 후 getReferenceById가 돌려줄 프록시를 흉내낸 엔티티. */
    private RefreshToken persistedRefreshToken(String familyId) {
        return RefreshToken.builder()
                .tokenHash("irrelevant-for-these-tests")
                .familyId(familyId)
                .user(user)
                .clientId("oidc-client")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
    }

    /** insertIfAbsentReturningId 호출을 성공(새 id 반환)으로 스텁하고, getReferenceById도 준비해준다. */
    private void stubSuccessfulInsert(String familyId) {
        when(refreshTokenRepository.insertIfAbsentReturningId(anyString(), eq(familyId), any(), anyString(), any()))
                .thenReturn(Optional.of(42L));
        when(refreshTokenRepository.getReferenceById(42L))
                .thenReturn(persistedRefreshToken(familyId));
    }

    @Test
    void save_records_new_refresh_token_with_family_id_equal_to_authorization_id() {
        when(refreshTokenRepository.findFirstByFamilyIdAndRevokedFalse(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);
        stubSuccessfulInsert("auth-1");

        OAuth2Authorization authorization = authorizationWithRefreshToken("auth-1", "raw-refresh-token-v1");

        service.save(authorization);

        verify(delegate).save(any(OAuth2Authorization.class));
        verify(refreshTokenRepository).insertIfAbsentReturningId(anyString(), eq("auth-1"), any(), eq("oidc-client"), any());
        verify(refreshTokenRepository, never()).bulkRevokeByFamilyId(eq("auth-1"), any(), eq("system-rotated"));

        RefreshTokenHistory capturedHistory = captureLastSavedHistory();
        assertThat(capturedHistory.getEventType()).isEqualTo(RefreshTokenEventType.ISSUED);
        assertThat(capturedHistory.getFamilyId()).isEqualTo("auth-1"); // authorization.getId()를 family_id로 재사용
    }

    @Test
    void save_skips_history_when_insert_is_ignored_due_to_duplicate() {
        // insertIfAbsentReturningId가 빈 Optional(이미 존재해서 무시됨)을 반환하면,
        // 같은 authorization을 중복 save()한 것으로 보고 히스토리도 남기지 않아야 한다.
        when(refreshTokenRepository.findFirstByFamilyIdAndRevokedFalse(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);
        when(refreshTokenRepository.insertIfAbsentReturningId(anyString(), anyString(), any(), anyString(), any()))
                .thenReturn(Optional.empty());

        OAuth2Authorization authorization = authorizationWithRefreshToken("auth-dup", "raw-refresh-token-v1");

        service.save(authorization);

        verify(delegate).save(any(OAuth2Authorization.class)); // delegate 저장은 여전히 일어남
        verify(refreshTokenHistoryRepository, never()).save(any(RefreshTokenHistory.class));
        verify(refreshTokenRepository, never()).getReferenceById(anyLong()); // 삽입 실패 시 참조도 안 만듦
    }

    @Test
    void save_sends_delegate_a_copy_with_redacted_refresh_token_value() {
        // oauth2_authorization.refresh_token_value에 원문이 새지 않아야 한다 —
        // delegate로 넘어가는 객체의 refresh_token 값은 원문과 달라야 함.
        when(refreshTokenRepository.findFirstByFamilyIdAndRevokedFalse(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);
        stubSuccessfulInsert("auth-redact");

        OAuth2Authorization authorization = authorizationWithRefreshToken("auth-redact", "raw-refresh-token-v1");

        service.save(authorization);

        ArgumentCaptor<OAuth2Authorization> captor = ArgumentCaptor.forClass(OAuth2Authorization.class);
        verify(delegate).save(captor.capture());

        OAuth2Authorization sentToDelegate = captor.getValue();
        assertThat(sentToDelegate.getRefreshToken().getToken().getTokenValue())
                .isNotEqualTo("raw-refresh-token-v1");
        // id/principalName 등 다른 필드는 원본 그대로 유지되어야 함
        assertThat(sentToDelegate.getId()).isEqualTo("auth-redact");
        assertThat(sentToDelegate.getPrincipalName()).isEqualTo("lee@haenaryn.com");
    }

    @Test
    void save_called_again_with_new_refresh_token_bulk_revokes_previous_and_marks_history_rotated() {
        RefreshToken previous = RefreshToken.builder()
                .tokenHash(TokenHasher.sha256("raw-refresh-token-v1"))
                .familyId("auth-1")
                .user(user)
                .clientId("oidc-client")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        when(refreshTokenRepository.findFirstByFamilyIdAndRevokedFalse("auth-1")).thenReturn(Optional.of(previous));
        when(userRepository.findByEmail("lee@haenaryn.com")).thenReturn(Optional.of(user));
        when(registeredClientRepository.findById("internal-client-id")).thenReturn(registeredClient);
        stubSuccessfulInsert("auth-1");

        // 같은 authorization id(=family_id), 새 refresh token 값 -> rotation으로 취급돼야 함
        OAuth2Authorization rotated = authorizationWithRefreshToken("auth-1", "raw-refresh-token-v2");

        service.save(rotated);

        // 실제 폐기는 벌크 UPDATE 한 번으로 처리 — DB 위임이라 mock에선 이 호출 자체를 검증
        verify(refreshTokenRepository).bulkRevokeByFamilyId(eq("auth-1"), any(), eq("system-rotated"));

        RefreshTokenHistory capturedHistory = captureLastSavedHistory();
        assertThat(capturedHistory.getEventType()).isEqualTo(RefreshTokenEventType.ROTATED);
        assertThat(capturedHistory.getPreviousToken()).isSameAs(previous);
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
    void findByToken_with_non_refresh_token_type_skips_our_ledger_entirely() {
        // tokenType이 REFRESH_TOKEN이 아님이 명확하면, 우리 refresh_tokens 테이블을
        // 조회할 것도 없이 바로 delegate로 위임해야 한다 (성능 최적화 — 헛도는 조회 제거).
        OAuth2Authorization expected = authorizationWithRefreshToken("auth-access", "some-access-token-value");
        when(delegate.findByToken("some-access-token-value", OAuth2TokenType.ACCESS_TOKEN)).thenReturn(expected);

        OAuth2Authorization result = service.findByToken("some-access-token-value", OAuth2TokenType.ACCESS_TOKEN);

        assertThat(result).isSameAs(expected);
        verify(refreshTokenRepository, never()).findByTokenHash(anyString()); // 짧은 회로로 아예 안 불림
    }

    @Test
    void findByToken_with_refresh_token_type_still_checks_our_ledger() {
        // REFRESH_TOKEN으로 명시된 경우는 짧은 회로를 타지 않고 기존처럼 우리 테이블을 먼저 확인해야 한다.
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        OAuth2Authorization expected = authorizationWithRefreshToken("auth-rt", "some-refresh-token-value");
        when(delegate.findByToken("some-refresh-token-value", OAuth2TokenType.REFRESH_TOKEN)).thenReturn(expected);

        OAuth2Authorization result = service.findByToken("some-refresh-token-value", OAuth2TokenType.REFRESH_TOKEN);

        assertThat(result).isSameAs(expected);
        verify(refreshTokenRepository).findByTokenHash(anyString()); // 짧은 회로를 타지 않고 정상적으로 우리 테이블 확인
    }

    @Test
    void findByToken_with_valid_ledger_entry_looks_up_delegate_by_id_not_by_token_value() {
        // delegate에는 redacted 값만 있으므로, 유효한 토큰이 확인되면 원문이 아니라
        // family_id(=authorization id)로 delegate.findById()를 호출해야 한다.
        RefreshToken valid = RefreshToken.builder()
                .tokenHash(TokenHasher.sha256("valid-refresh-token"))
                .familyId("auth-valid")
                .user(user)
                .clientId("oidc-client")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(valid));
        OAuth2Authorization expected = authorizationWithRefreshToken("auth-valid", "redacted");
        when(delegate.findById("auth-valid")).thenReturn(expected);

        OAuth2Authorization result = service.findByToken("valid-refresh-token", OAuth2TokenType.REFRESH_TOKEN);

        assertThat(result).isSameAs(expected);
        verify(delegate).findById("auth-valid");
        verify(delegate, never()).findByToken(eq("valid-refresh-token"), any());
    }

    @Test
    void findByToken_with_already_revoked_token_triggers_reuse_detection() {
        RefreshToken revoked = RefreshToken.builder()
                .tokenHash(TokenHasher.sha256("stolen-token"))
                .familyId("auth-3")
                .user(user)
                .clientId("oidc-client")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
        revoked.revoke("system-rotated"); // 이미 한 번 교체되어 폐기된 상태

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(revoked));
        OAuth2Authorization compromised = authorizationWithRefreshToken("auth-3", "redacted");
        when(delegate.findById("auth-3")).thenReturn(compromised);

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
