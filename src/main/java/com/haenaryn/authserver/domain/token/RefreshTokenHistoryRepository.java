package com.haenaryn.authserver.domain.token;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RefreshTokenHistoryRepository extends JpaRepository<RefreshTokenHistory, Long> {

    List<RefreshTokenHistory> findAllByUserIdOrderByOccurredAtDesc(Long userId);

    List<RefreshTokenHistory> findAllByFamilyIdOrderByOccurredAtDesc(String familyId);
}
