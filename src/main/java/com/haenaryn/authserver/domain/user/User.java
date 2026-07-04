package com.haenaryn.authserver.domain.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    private String name;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "account_locked", nullable = false)
    private boolean accountLocked;

    /** 잠긴 시각. 자동 잠금 해제(loginFailWindowHours 경과) 판단에 사용. */
    @Column(name = "account_locked_at")
    private LocalDateTime accountLockedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Builder
    private User(String email, String passwordHash, String name) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.name = name;
        this.enabled = true;
        this.accountLocked = false;
    }

    public void lockAccount() {
        this.accountLocked = true;
        this.accountLockedAt = LocalDateTime.now();
    }

    public void unlockAccount() {
        this.accountLocked = false;
        this.accountLockedAt = null;
    }

    /** 잠금 후 지정된 시간이 지났으면 true — 자동 잠금 해제 판단용. */
    public boolean isLockExpired(long windowHours) {
        return accountLocked && accountLockedAt != null
                && accountLockedAt.plusHours(windowHours).isBefore(LocalDateTime.now());
    }
}
