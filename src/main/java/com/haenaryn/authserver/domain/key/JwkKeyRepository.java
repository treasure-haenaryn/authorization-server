package com.haenaryn.authserver.domain.key;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface JwkKeyRepository extends JpaRepository<JwkKeyEntity, Long> {

    List<JwkKeyEntity> findAllByActiveTrue();

    Optional<JwkKeyEntity> findByKeyId(String keyId);
}
