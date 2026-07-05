package com.haenaryn.authserver.health;

import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * bucket4j 전용 Lettuce 연결 상태를 /actuator/health에 노출하는 커스텀 인디케이터 검증.
 * 이 연결은 Spring Data Redis의 RedisConnectionFactory를 거치지 않으므로, 기본
 * RedisHealthIndicator 대신 RateLimitRedisHealthIndicator를 사용
 */
@ExtendWith(MockitoExtension.class)
class RateLimitRedisHealthIndicatorTest {

    @Mock
    private StatefulRedisConnection<String, byte[]> connection;
    @Mock
    private RedisCommands<String, byte[]> commands;

    private RateLimitRedisHealthIndicator indicator;

    @BeforeEach
    void setUp() {
        indicator = new RateLimitRedisHealthIndicator(connection);
    }

    @Test
    void reports_up_when_connection_is_open_and_ping_succeeds() {
        when(connection.isOpen()).thenReturn(true);
        when(connection.sync()).thenReturn(commands);
        when(commands.ping()).thenReturn("PONG");

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void reports_down_when_connection_is_closed() {
        when(connection.isOpen()).thenReturn(false);

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("reason", "connection closed");
    }

    @Test
    void reports_down_when_ping_throws() {
        when(connection.isOpen()).thenReturn(true);
        when(connection.sync()).thenThrow(new RuntimeException("Redis connection refused"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }
}
