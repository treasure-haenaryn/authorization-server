package com.haenaryn.authserver.integration;

import com.haenaryn.authserver.integration.support.OAuth2AuthorizationCodeFlowHelper;
import com.haenaryn.authserver.integration.support.PartmanPostgresImage;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JWKS/OIDC 디스커버리가 인증 헤더 없이도 200이어야 함을 검증한다 — authorizeHttpRequests에
 * 명시적 permitAll이 빠져있어 로그인 화면으로 리다이렉트되던 회귀 버그의 재발 방지용.
 */
@Tag("integration")
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwksPublicAccessIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(PartmanPostgresImage.NAME)
            .withDatabaseName("authserver")
            .withUsername("authserver")
            .withPassword("authserver");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    @LocalServerPort
    private int port;

    @Test
    void jwks_endpoint_is_publicly_accessible_without_authentication() {
        RestTemplate restTemplate = OAuth2AuthorizationCodeFlowHelper.newRestTemplate();

        ResponseEntity<String> response = restTemplate.getForEntity(baseUrl() + "/oauth2/jwks", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"keys\"");
    }

    @Test
    void oidc_discovery_endpoint_is_publicly_accessible_without_authentication() {
        RestTemplate restTemplate = OAuth2AuthorizationCodeFlowHelper.newRestTemplate();

        ResponseEntity<String> response = restTemplate.getForEntity(
                baseUrl() + "/.well-known/openid-configuration", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private String baseUrl() {
        return "http://localhost:" + port;
    }
}
