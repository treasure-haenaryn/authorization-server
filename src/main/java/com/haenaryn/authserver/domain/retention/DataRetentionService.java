package com.haenaryn.authserver.domain.retention;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * audit_logs/refresh_token_histories의 파티션 사전 생성/보존 기간 정리는 pg_partman에 위임한다.
 * 이 클래스는 그 유지보수 프로시저를 호출만 한다. 파티션 생성 주기·보존 기간 자체는
 * V11 마이그레이션의 partman.part_config 설정을 따른다.
 */
@Service
public class DataRetentionService {

    private static final Logger log = LoggerFactory.getLogger(DataRetentionService.class);

    private final JdbcTemplate jdbcTemplate;

    public DataRetentionService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /** pg_partman의 유지보수 프로시저를 호출해 파티션 생성/만료 정리를 한 번에 처리한다. */
    public void runPartitionMaintenance() {
        jdbcTemplate.execute("CALL partman.run_maintenance_proc()");
        log.info("pg_partman run_maintenance_proc 실행 완료");
    }
}
