package com.haenaryn.authserver.domain.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUserIdAndRevokedFalse(Long userId);

    List<RefreshToken> findAllByUserId(Long userId);

    List<RefreshToken> findAllByFamilyId(String familyId);

    /** rotation 이력 기록용 단건 조회 (family_id당 활성 토큰은 최대 1개). */
    Optional<RefreshToken> findFirstByFamilyIdAndRevokedFalse(String familyId);

    @Query(value = """
            INSERT INTO refresh_tokens (token_hash, family_id, user_id, client_id, expires_at)
            VALUES (:tokenHash, :familyId, :userId, :clientId, :expiresAt)
            ON CONFLICT ON CONSTRAINT uq_refresh_tokens_token_hash DO NOTHING
            RETURNING id
            """, nativeQuery = true)
    Optional<Long> insertIfAbsentReturningId(@Param("tokenHash") String tokenHash,
                                              @Param("familyId") String familyId,
                                              @Param("userId") Long userId,
                                              @Param("clientId") String clientId,
                                              @Param("expiresAt") LocalDateTime expiresAt);

    /** familyId 체인 전체를 한 번의 UPDATE로 폐기 (rotation, 재사용 감지, 로그아웃 등). */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t
            SET t.revoked = true, t.revokedAt = :revokedAt, t.revokedBy = :revokedBy
            WHERE t.familyId = :familyId AND t.revoked = false
            """)
    int bulkRevokeByFamilyId(@Param("familyId") String familyId,
                              @Param("revokedAt") LocalDateTime revokedAt,
                              @Param("revokedBy") String revokedBy);

    /** 유저 전체 세션(모든 familyId) 강제 로그아웃용. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t
            SET t.revoked = true, t.revokedAt = :revokedAt, t.revokedBy = :revokedBy
            WHERE t.user.id = :userId AND t.revoked = false
            """)
    int bulkRevokeByUserId(@Param("userId") Long userId,
                            @Param("revokedAt") LocalDateTime revokedAt,
                            @Param("revokedBy") String revokedBy);
}
