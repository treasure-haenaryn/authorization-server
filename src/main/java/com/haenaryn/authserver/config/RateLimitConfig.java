package com.haenaryn.authserver.config;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Rate Limiting(bucket4j 토큰 버킷)이 사용할 전용 Lettuce 연결을 구성한다.
 */
@Configuration
public class RateLimitConfig {

    @Bean(destroyMethod = "shutdown")
    public RedisClient bucket4jRedisClient(@Value("${spring.data.redis.host}") String host,
                                            @Value("${spring.data.redis.port}") int port,
                                            @Value("${spring.data.redis.password:}") String password,
                                            @Value("${spring.data.redis.connect-timeout:2s}") Duration connectTimeout,
                                            @Value("${spring.data.redis.timeout:2s}") Duration commandTimeout) {
        RedisURI.Builder uriBuilder = RedisURI.builder().withHost(host).withPort(port).withTimeout(commandTimeout);
        if (password != null && !password.isBlank()) {
            uriBuilder.withPassword(password.toCharArray());
        }
        RedisClient redisClient = RedisClient.create(uriBuilder.build());
        redisClient.setOptions(ClientOptions.builder()
                .socketOptions(SocketOptions.builder().connectTimeout(connectTimeout).build())
                .build());
        return redisClient;
    }

    @Bean(destroyMethod = "close")
    public StatefulRedisConnection<String, byte[]> bucket4jRedisConnection(RedisClient redisClient) {
        RedisCodec<String, byte[]> codec = RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE);
        return redisClient.connect(codec);
    }

    @Bean
    public LettuceBasedProxyManager<String> rateLimitProxyManager(StatefulRedisConnection<String, byte[]> connection) {
        return Bucket4jLettuce.casBasedBuilder(connection)
                .expirationAfterWrite(ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(Duration.ofMinutes(5)))
                .build();
    }
}
