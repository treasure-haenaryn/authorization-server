package com.haenaryn.authserver.domain.key;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * 운영환경(prod)에서 사용하는 EC(ES256) 서명키의 DB 저장 형태.
 * {@code encryptedPrivateKey}는 AES-256으로 암호화된 값이 저장되며, status는
 * ACTIVE -> RETIRING -> RETIRED 순으로 전이한다.
 */
@Entity
@Table(name = "jwk_keys")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class JwkKeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_id", nullable = false, unique = true)
    private String keyId;

    @Column(nullable = false)
    private String curve;

    @Column(nullable = false)
    private String algorithm;

    /** RETIRED 전환 시 null로 wipe된다. */
    @Column(name = "encrypted_private_key")
    private String encryptedPrivateKey;

    @Column(name = "public_key", nullable = false)
    private String publicKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private KeyStatus status;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

    /** RETIRING -> RETIRED 전환 예정 시각. */
    @Column(name = "grace_expires_at")
    private LocalDateTime graceExpiresAt;

    @Column(name = "retired_at")
    private LocalDateTime retiredAt;

    @Builder
    private JwkKeyEntity(String keyId, String curve, String algorithm,
                          String encryptedPrivateKey, String publicKey) {
        this.keyId = keyId;
        this.curve = curve;
        this.algorithm = algorithm;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.publicKey = publicKey;
        this.status = KeyStatus.ACTIVE;
        this.activatedAt = LocalDateTime.now();
    }

    /** ACTIVE -> RETIRING 전환. 서명에는 더 이상 쓰이지 않고 grace period 동안 검증에만 남는다. */
    public void beginRetirement(LocalDateTime graceExpiresAt) {
        if (this.status != KeyStatus.ACTIVE) {
            throw new IllegalStateException("ACTIVE 상태의 키만 RETIRING으로 전환할 수 있습니다. 현재 status=" + this.status);
        }
        this.status = KeyStatus.RETIRING;
        this.graceExpiresAt = graceExpiresAt;
    }

    /** RETIRING -> RETIRED 전환. 개인키 값을 wipe한다. */
    public void finalizeRetirement() {
        if (this.status != KeyStatus.RETIRING) {
            throw new IllegalStateException("RETIRING 상태의 키만 RETIRED로 전환할 수 있습니다. 현재 status=" + this.status);
        }
        this.status = KeyStatus.RETIRED;
        this.retiredAt = LocalDateTime.now();
        this.encryptedPrivateKey = null;
    }
}
