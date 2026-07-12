package com.haenaryn.authserver.integration.support;

import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.DockerImageName;

import java.nio.file.Path;

/**
 * V11 마이그레이션이 pg_partman 익스텐션을 요구해서, 순정 {@code postgres:16} 이미지로는
 * Testcontainers 통합 테스트가 Flyway 마이그레이션 단계에서 실패한다
 * ({@code extension "pg_partman" is not available}). {@code docker/postgres.Dockerfile}로
 * pg_partman이 설치된 이미지를 직접 빌드해서, 모든 통합 테스트가 이 상수 하나를 공유해서 쓴다
 * (정적 초기화 시 1회만 빌드됨).
 */
public final class PartmanPostgresImage {

    public static final DockerImageName NAME = DockerImageName.parse(
            new ImageFromDockerfile("authserver-test/postgres-partman", false)
                    .withDockerfile(Path.of("docker/postgres.Dockerfile"))
                    .get()
    ).asCompatibleSubstituteFor("postgres");

    private PartmanPostgresImage() {
    }
}
