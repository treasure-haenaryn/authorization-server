package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * rotate()/sweepExpiredRetiring()의 상태 전이가 올바른 순서(RETIRING 전환 flush -> 신규 ACTIVE
 * insert)로 일어나는지, grace period 계산과 감사 로그 발행이 정확한지 검증한다.
 * 락(RedisDistributedLock)은 이 서비스의 책임이 아니므로(호출부 책임) 여기서는 다루지 않는다.
 */
@ExtendWith(MockitoExtension.class)
class KeyRotationServiceTest {

    // 32바이트(AES-256) 테스트용 키. 실제 값은 중요하지 않고 길이만 맞으면 된다.
    private static final String ENCRYPTION_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private static final AuthServerProperties.SigningKey SIGNING_KEY = new AuthServerProperties.SigningKey(
            AuthServerProperties.SigningKeySourceType.DATABASE, ENCRYPTION_KEY, 90, 60, 30);

    @Mock
    private JwkKeyRepository jwkKeyRepository;
    @Mock
    private AuditLogService auditLogService;

    private KeyRotationService service;

    @BeforeEach
    void setUp() {
        AuthServerProperties properties = new AuthServerProperties(null, null, null, SIGNING_KEY, null);
        service = new KeyRotationService(jwkKeyRepository, properties, auditLogService);
    }

    @Test
    void rotate_creates_first_active_key_when_none_exists() {
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE)).thenReturn(Optional.empty());

        KeyRotationService.RotationResult result = service.rotate("bootstrap");

        assertThat(result.newKeyId()).isNotBlank();
        assertThat(result.previousKeyId()).isNull();
        verify(jwkKeyRepository, never()).saveAndFlush(any());

        ArgumentCaptor<JwkKeyEntity> savedCaptor = ArgumentCaptor.forClass(JwkKeyEntity.class);
        verify(jwkKeyRepository).save(savedCaptor.capture());
        assertThat(savedCaptor.getValue().getStatus()).isEqualTo(KeyStatus.ACTIVE);
        assertThat(savedCaptor.getValue().getKeyId()).isEqualTo(result.newKeyId());

        verify(auditLogService).record(eq(AuditEventType.SIGNING_KEY_ROTATED), eq("system"),
                contains("previousKid=null"));
    }

    @Test
    void rotate_retires_existing_active_key_before_inserting_new_one() {
        JwkKeyEntity existingActive = JwkKeyEntity.builder()
                .keyId("old-kid")
                .curve("P-256")
                .algorithm("ES256")
                .encryptedPrivateKey("encrypted")
                .publicKey("{}")
                .build();
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE))
                .thenReturn(Optional.of(existingActive));

        KeyRotationService.RotationResult result = service.rotate("scheduled");

        // 기존 키는 RETIRING으로 전환되어 saveAndFlush로 즉시 flush되어야 한다 (신규 INSERT보다 먼저).
        assertThat(existingActive.getStatus()).isEqualTo(KeyStatus.RETIRING);
        assertThat(existingActive.getGraceExpiresAt()).isNotNull();
        verify(jwkKeyRepository).saveAndFlush(existingActive);

        assertThat(result.previousKeyId()).isEqualTo("old-kid");
        assertThat(result.newKeyId()).isNotEqualTo("old-kid");

        verify(auditLogService).record(eq(AuditEventType.SIGNING_KEY_ROTATED), eq("system"),
                contains("previousKid=old-kid"));
    }

    @Test
    void sweepExpiredRetiring_finalizes_expired_keys_and_wipes_private_key() {
        JwkKeyEntity expired = JwkKeyEntity.builder()
                .keyId("expired-kid")
                .curve("P-256")
                .algorithm("ES256")
                .encryptedPrivateKey("still-encrypted")
                .publicKey("{}")
                .build();
        expired.beginRetirement(LocalDateTime.now().minusMinutes(1));

        when(jwkKeyRepository.findAllByStatusAndGraceExpiresAtBefore(eq(KeyStatus.RETIRING), any()))
                .thenReturn(List.of(expired));

        int count = service.sweepExpiredRetiring();

        assertThat(count).isEqualTo(1);
        assertThat(expired.getStatus()).isEqualTo(KeyStatus.RETIRED);
        assertThat(expired.getEncryptedPrivateKey()).isNull();
        assertThat(expired.getRetiredAt()).isNotNull();
        verify(auditLogService).record(eq(AuditEventType.SIGNING_KEY_RETIRED), eq("system"), contains("expired-kid"));
    }

    @Test
    void sweepExpiredRetiring_returns_zero_when_nothing_expired() {
        when(jwkKeyRepository.findAllByStatusAndGraceExpiresAtBefore(eq(KeyStatus.RETIRING), any()))
                .thenReturn(List.of());

        assertThat(service.sweepExpiredRetiring()).isZero();
        verify(auditLogService, never()).record(eq(AuditEventType.SIGNING_KEY_RETIRED), anyString(), anyString());
    }

    @Test
    void isRotationDue_true_when_no_active_key() {
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE)).thenReturn(Optional.empty());

        assertThat(service.isRotationDue()).isTrue();
    }

    @Test
    void isRotationDue_false_when_active_key_is_recent() {
        JwkKeyEntity recentActive = JwkKeyEntity.builder()
                .keyId("recent-kid").curve("P-256").algorithm("ES256")
                .encryptedPrivateKey("encrypted").publicKey("{}")
                .build();
        when(jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE))
                .thenReturn(Optional.of(recentActive));

        assertThat(service.isRotationDue()).isFalse();
    }
}
