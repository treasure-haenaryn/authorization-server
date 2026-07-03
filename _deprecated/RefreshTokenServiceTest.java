package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Spring Authorization Server 파이프라인과 무관하게, RefreshTokenService의 발급/교체/
 * 재사용감지 로직 자체만 검증하는 순수 단위 테스트. 실제 DB(H2/PostgreSQL) 없이
 * Mockito로 리포지토리를 흉내낸다.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenHistoryRepository refreshTokenHistoryRepository;

    private RefreshTokenService refreshTokenService;
    private User user;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, refreshTokenHistoryRepository);
        user = User.builder()
                .email("lee@haenaryn.com")
                .passwordHash("hashed-password")
                .build();

        // save() 호출 시 넘겨받은 엔티티를 그대로 반환하도록 스텁 (실제 DB 없이 서비스 로직만 검증)
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void issueInitial_creates_new_family_and_ISSUED_history() {
        IssuedRefreshToken issued = refreshTokenService.issueInitial(
                user, "test-client", "iPhone 15", "127.0.0.1", Duration.ofDays(7)
        );

        assertThat(issued.rawToken()).isNotBlank();
        assertThat(issued.entity().getFamilyId()).isNotBlank();
        assertThat(issued.entity().getTokenHash()).isEqualTo(TokenHasher.sha256(issued.rawToken()));
        assertThat(issued.entity().isRevoked()).isFalse();

        ArgumentCaptor<RefreshTokenHistory> historyCaptor = ArgumentCaptor.forClass(RefreshTokenHistory.class);
        verify(refreshTokenHistoryRepository).save(historyCaptor.capture());
        assertThat(historyCaptor.getValue().getEventType()).isEqualTo(RefreshTokenEventType.ISSUED);
        assertThat(historyCaptor.getValue().getFamilyId()).isEqualTo(issued.entity().getFamilyId());
    }

    @Test
    void rotate_revokes_previous_and_issues_new_token_with_same_family_id() {
        RefreshToken previous = existingActiveToken("family-1");
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(previous));

        IssuedRefreshToken issued = refreshTokenService.rotate("presented-raw-token", "iPhone 15", "127.0.0.1", Duration.ofDays(7));

        assertThat(previous.isRevoked()).isTrue();
        assertThat(previous.getRevokedBy()).isEqualTo("system-rotated");
        assertThat(issued.entity().getFamilyId()).isEqualTo("family-1"); // family_id 유지 확인
        assertThat(issued.entity().isRevoked()).isFalse();

        verify(refreshTokenRepository, never()).bulkRevokeByFamilyId(anyString(), any(), anyString());

        ArgumentCaptor<RefreshTokenHistory> historyCaptor = ArgumentCaptor.forClass(RefreshTokenHistory.class);
        verify(refreshTokenHistoryRepository).save(historyCaptor.capture());
        assertThat(historyCaptor.getValue().getEventType()).isEqualTo(RefreshTokenEventType.ROTATED);
    }

    @Test
    void rotate_with_already_revoked_token_triggers_reuse_detection_and_revokes_entire_family() {
        RefreshToken alreadyRevoked = existingActiveToken("family-2");
        alreadyRevoked.revoke("system-rotated"); // 이미 한 번 교체되어 폐기된 상태를 흉내냄
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(alreadyRevoked));

        assertThatThrownBy(() ->
                refreshTokenService.rotate("stolen-old-token", "unknown-device", "10.0.0.99", Duration.ofDays(7))
        )
                .isInstanceOf(RefreshTokenReuseDetectedException.class)
                .hasMessageContaining("family-2");

        verify(refreshTokenRepository).bulkRevokeByFamilyId(eq("family-2"), any(LocalDateTime.class), eq("system-reuse-detected"));
        // 재사용 감지 시에는 새 토큰을 발급하면 안 된다 — save()가 호출되지 않아야 함
        verify(refreshTokenRepository, never()).save(any());

        ArgumentCaptor<RefreshTokenHistory> historyCaptor = ArgumentCaptor.forClass(RefreshTokenHistory.class);
        verify(refreshTokenHistoryRepository).save(historyCaptor.capture());
        assertThat(historyCaptor.getValue().getEventType()).isEqualTo(RefreshTokenEventType.REUSE_DETECTED);
    }

    @Test
    void rotate_with_unknown_token_throws_invalid_refresh_token_exception() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                refreshTokenService.rotate("never-issued-token", "device", "127.0.0.1", Duration.ofDays(7))
        ).isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenHistoryRepository, never()).save(any());
    }

    @Test
    void rotate_with_expired_token_throws_invalid_refresh_token_exception() {
        RefreshToken expired = RefreshToken.builder()
                .tokenHash("expired-hash")
                .familyId("family-3")
                .user(user)
                .clientId("test-client")
                .expiresAt(LocalDateTime.now().minusMinutes(1)) // 이미 만료
                .build();
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(expired));

        assertThatThrownBy(() ->
                refreshTokenService.rotate("expired-raw-token", "device", "127.0.0.1", Duration.ofDays(7))
        ).isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenRepository, never()).bulkRevokeByFamilyId(anyString(), any(), anyString());
    }

    private RefreshToken existingActiveToken(String familyId) {
        return RefreshToken.builder()
                .tokenHash("previous-token-hash")
                .familyId(familyId)
                .user(user)
                .clientId("test-client")
                .deviceInfo("old-device")
                .ipAddress("127.0.0.1")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
    }
}
