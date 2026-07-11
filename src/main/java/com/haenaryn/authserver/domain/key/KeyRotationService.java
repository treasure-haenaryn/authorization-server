package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.config.AuthServerProperties;
import com.haenaryn.authserver.config.EcKeyGenerator;
import com.haenaryn.authserver.crypto.AesGcmCipher;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import com.nimbusds.jose.jwk.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * 서명키 생성/로테이션의 DB 트랜잭션 로직. 락 획득/해제는 호출부
 * ({@link KeyRotationScheduler}, {@link JwkKeyBootstrap})의 책임이다.
 */
@Service
public class KeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationService.class);
    private static final String SYSTEM_PRINCIPAL = "system";

    private final JwkKeyRepository jwkKeyRepository;
    private final AuthServerProperties properties;
    private final AuditLogService auditLogService;

    public KeyRotationService(JwkKeyRepository jwkKeyRepository,
                               AuthServerProperties properties,
                               AuditLogService auditLogService) {
        this.jwkKeyRepository = jwkKeyRepository;
        this.properties = properties;
        this.auditLogService = auditLogService;
    }

    /** ACTIVE 키가 rotation-interval-days를 넘겼는지, 또는 아예 없는지 확인한다. */
    public boolean isRotationDue() {
        LocalDateTime now = LocalDateTime.now();
        Duration rotationInterval = Duration.ofDays(properties.signingKey().rotationIntervalDays());
        return jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE)
                .map(active -> KeyRotationPolicy.isRotationDue(active.getActivatedAt(), rotationInterval, now))
                .orElse(true);
    }

    /**
     * 새 EC 키를 ACTIVE로 등록하고, 기존 ACTIVE 키는 RETIRING으로 내린다(있는 경우).
     * ACTIVE 키가 없는 상태(최초 부트스트랩)에서 호출해도 그대로 동작한다.
     */
    @Transactional
    public RotationResult rotate(String reason) {
        LocalDateTime now = LocalDateTime.now();
        Optional<JwkKeyEntity> currentActive = jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE);

        // saveAndFlush로 순서 고정 필요 (Hibernate 기본 flush 순서 관련) — 상세: Obsidian QA #16
        currentActive.ifPresent(prev -> {
            LocalDateTime graceExpiresAt = KeyRotationPolicy.graceDeadline(
                    now, Duration.ofMinutes(properties.signingKey().gracePeriodMinutes()));
            prev.beginRetirement(graceExpiresAt);
            jwkKeyRepository.saveAndFlush(prev);
        });

        ECKey newKey = EcKeyGenerator.generate();
        AesGcmCipher cipher = new AesGcmCipher(properties.signingKey().encryptionKey());
        JwkKeyEntity newEntity = JwkKeyEntity.builder()
                .keyId(newKey.getKeyID())
                .curve(newKey.getCurve().getName())
                .algorithm(newKey.getAlgorithm().getName())
                .encryptedPrivateKey(cipher.encrypt(newKey.toJSONString()))
                .publicKey(newKey.toPublicJWK().toJSONString())
                .build();
        jwkKeyRepository.save(newEntity);

        String previousKid = currentActive.map(JwkKeyEntity::getKeyId).orElse(null);
        log.info("서명키 로테이션 완료: reason={}, previousKid={}, newKid={}", reason, previousKid, newKey.getKeyID());
        auditLogService.record(AuditEventType.SIGNING_KEY_ROTATED, SYSTEM_PRINCIPAL,
                "reason=%s, previousKid=%s, newKid=%s".formatted(reason, previousKid, newKey.getKeyID()));

        return new RotationResult(newKey.getKeyID(), previousKid);
    }

    /** grace period가 지난 RETIRING 키를 RETIRED로 전환한다(개인키 wipe 포함). */
    @Transactional
    public int sweepExpiredRetiring() {
        List<JwkKeyEntity> expired = jwkKeyRepository.findAllByStatusAndGraceExpiresAtBefore(
                KeyStatus.RETIRING, LocalDateTime.now());

        for (JwkKeyEntity key : expired) {
            key.finalizeRetirement();
            log.info("서명키 완전 폐기(RETIRED): kid={}", key.getKeyId());
            auditLogService.record(AuditEventType.SIGNING_KEY_RETIRED, SYSTEM_PRINCIPAL, "kid=" + key.getKeyId());
        }
        return expired.size();
    }

    public record RotationResult(String newKeyId, String previousKeyId) {
    }
}
