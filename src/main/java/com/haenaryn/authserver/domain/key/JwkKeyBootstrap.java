package com.haenaryn.authserver.domain.key;

import com.haenaryn.authserver.cache.RedisDistributedLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/**
 * {@code source=database} 모드에서 최초 기동 시 ACTIVE 키가 없으면
 * {@link KeyRotationService#rotate}로 첫 서명키를 생성한다.
 */
@Component
@ConditionalOnProperty(prefix = "auth-server.signing-key", name = "source", havingValue = "database")
public class JwkKeyBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(JwkKeyBootstrap.class);
    private static final String BOOTSTRAP_LOCK_KEY = "lock:jwk:bootstrap";
    private static final Duration LOCK_TTL = Duration.ofMinutes(1);

    private final JwkKeyRepository jwkKeyRepository;
    private final KeyRotationService keyRotationService;
    private final RedisDistributedLock lock;

    public JwkKeyBootstrap(JwkKeyRepository jwkKeyRepository,
                            KeyRotationService keyRotationService,
                            RedisDistributedLock lock) {
        this.jwkKeyRepository = jwkKeyRepository;
        this.keyRotationService = keyRotationService;
        this.lock = lock;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (hasActiveKey()) {
            return;
        }

        Optional<String> token = lock.tryLock(BOOTSTRAP_LOCK_KEY, LOCK_TTL);
        if (token.isEmpty()) {
            log.info("다른 인스턴스가 부트스트랩 중이거나 Redis 장애 — 이 인스턴스는 건너뜀 "
                    + "(ActiveSigningJwkSource가 다음 조회 시점에 다른 인스턴스가 만든 키를 읽는다)");
            return;
        }
        try {
            if (hasActiveKey()) {
                log.info("락 획득 사이 다른 인스턴스가 이미 초기 서명키를 생성함 — 건너뜀");
                return;
            }
            KeyRotationService.RotationResult result = keyRotationService.rotate("bootstrap");
            log.info("최초 서명키 부트스트랩 완료: kid={}", result.newKeyId());
        } finally {
            lock.unlock(BOOTSTRAP_LOCK_KEY, token.get());
        }
    }

    private boolean hasActiveKey() {
        return jwkKeyRepository.findFirstByStatusOrderByActivatedAtDesc(KeyStatus.ACTIVE).isPresent();
    }
}
