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

    /**
     * 재사용 감지(REUSE_DETECTED) 시 사용. familyId 하나로 체인 전체를 한 번의 UPDATE로 폐기한다.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t
            SET t.revoked = true, t.revokedAt = :revokedAt, t.revokedBy = :revokedBy
            WHERE t.familyId = :familyId AND t.revoked = false
            """)
    int bulkRevokeByFamilyId(@Param("familyId") String familyId,
                              @Param("revokedAt") LocalDateTime revokedAt,
                              @Param("revokedBy") String revokedBy);

    /**
     * 관리자가 유저 전체 세션(모든 familyId)을 강제 로그아웃시킬 때 사용
     */
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
