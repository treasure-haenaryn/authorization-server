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

    /** Redis 장애 시에만 쓰이는 로그인 실패 폴백 카운터. */
    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;

    /** 폴백 카운터의 윈도우 시작 시각. */
    @Column(name = "failed_login_window_started_at")
    private LocalDateTime failedLoginWindowStartedAt;

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

    /** Redis 장애 시 폴백 경로. 윈도우 경과/최초 실패면 1부터 다시 세고, 아니면 누적 증가. */
    public int registerFailedLoginFallback(long windowHours) {
        LocalDateTime now = LocalDateTime.now();
        if (failedLoginWindowStartedAt == null || failedLoginWindowStartedAt.plusHours(windowHours).isBefore(now)) {
            failedLoginCount = 1;
            failedLoginWindowStartedAt = now;
        } else {
            failedLoginCount++;
        }
        return failedLoginCount;
    }

    /** 로그인 성공 시 호출 — 폴백 카운터도 함께 리셋한다. */
    public void resetFailedLoginFallback() {
        this.failedLoginCount = 0;
        this.failedLoginWindowStartedAt = null;
    }
}
