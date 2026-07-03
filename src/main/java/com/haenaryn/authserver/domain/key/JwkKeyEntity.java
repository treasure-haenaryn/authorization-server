package com.haenaryn.authserver.domain.key;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * 운영환경(prod)에서 사용하는 EC(ES256) 서명키의 DB 저장 형태.
 * {@code encryptedPrivateKey}는 AES-256으로 암호화된 값이 저장.
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

    @Lob
    @Column(name = "encrypted_private_key", nullable = false)
    private String encryptedPrivateKey;

    @Lob
    @Column(name = "public_key", nullable = false)
    private String publicKey;

    @Column(nullable = false)
    private boolean active;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

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
        this.active = true;
    }

    public void retire() {
        this.active = false;
        this.retiredAt = LocalDateTime.now();
    }
}
