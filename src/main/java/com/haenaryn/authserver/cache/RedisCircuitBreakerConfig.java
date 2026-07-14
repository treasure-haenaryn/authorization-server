package com.haenaryn.authserver.cache;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Redis 호출을 감싸는 공용 서킷브레이커 빈. Redis가 느려질 때 요청 스레드가 타임아웃까지
 * 블로킹되는 걸 막는다.
 */
@Configuration
public class RedisCircuitBreakerConfig {

    @Bean
    public CircuitBreaker redisCircuitBreaker() {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .minimumNumberOfCalls(10)
                .failureRateThreshold(50)
                // spring.data.redis.timeout(500ms)과 맞춘 값 — 그 시간을 넘기면 "느린 호출"로 집계
                .slowCallDurationThreshold(Duration.ofMillis(500))
                .slowCallRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(10))
                .permittedNumberOfCallsInHalfOpenState(5)
                .build();
        return CircuitBreaker.of("redis", config);
    }
}
