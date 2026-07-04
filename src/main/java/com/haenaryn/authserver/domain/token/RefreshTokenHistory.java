package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Refresh Token Rotation 이력.
 */
@Entity
@Table(name = "refresh_token_histories")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshTokenHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "family_id", nullable = false, length = 36)
    private String familyId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "previous_token_id")
    private RefreshToken previousToken;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "new_token_id")
    private RefreshToken newToken;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 30)
    private RefreshTokenEventType eventType;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "device_info")
    private String deviceInfo;

    @CreationTimestamp
    @Column(name = "occurred_at", nullable = false, updatable = false)
    private LocalDateTime occurredAt;

    @Builder
    private RefreshTokenHistory(User user, String familyId, RefreshToken previousToken, RefreshToken newToken,
                                 RefreshTokenEventType eventType, String ipAddress, String deviceInfo) {
        this.user = user;
        this.familyId = familyId;
        this.previousToken = previousToken;
        this.newToken = newToken;
        this.eventType = eventType;
        this.ipAddress = ipAddress;
        this.deviceInfo = deviceInfo;
    }
}
