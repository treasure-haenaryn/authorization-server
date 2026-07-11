package com.haenaryn.authserver.domain.key;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface JwkKeyRepository extends JpaRepository<JwkKeyEntity, Long> {

    Optional<JwkKeyEntity> findByKeyId(String keyId);

    /** 현재 서명에 쓰이는 단일 키. DB 유니크 인덱스로 최대 1건임이 보장된다. */
    Optional<JwkKeyEntity> findFirstByStatusOrderByActivatedAtDesc(KeyStatus status);

    /** JWKS(/.well-known/jwks.json) 및 JwtDecoder 검증용 노출 대상 — ACTIVE + RETIRING. */
    List<JwkKeyEntity> findAllByStatusIn(Collection<KeyStatus> statuses);

    /** grace period가 지나 RETIRED로 전환해야 하는 대상. */
    List<JwkKeyEntity> findAllByStatusAndGraceExpiresAtBefore(KeyStatus status, LocalDateTime cutoff);
}
