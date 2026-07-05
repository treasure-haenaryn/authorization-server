package com.haenaryn.authserver.health;

import io.lettuce.core.api.StatefulRedisConnection;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * bucket4j(Rate Limiting) 전용 Lettuce 연결의 상태를 {@code /actuator/health}에 노출한다.
 * readiness/liveness 그룹에는 포함하지 않는다.
 */
@Component
public class RateLimitRedisHealthIndicator implements HealthIndicator {

    private final StatefulRedisConnection<String, byte[]> connection;

    public RateLimitRedisHealthIndicator(StatefulRedisConnection<String, byte[]> connection) {
        this.connection = connection;
    }

    @Override
    public Health health() {
        try {
            if (!connection.isOpen()) {
                return Health.down().withDetail("reason", "connection closed").build();
            }
            connection.sync().ping();
            return Health.up().build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
