package com.haenaryn.authserver.domain.retention;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.mockito.Mockito.verify;

/** runPartitionMaintenance()가 pg_partman의 run_maintenance_proc()를 호출하는지만 검증한다. */
@ExtendWith(MockitoExtension.class)
class DataRetentionServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    private DataRetentionService service;

    @BeforeEach
    void setUp() {
        service = new DataRetentionService(jdbcTemplate);
    }

    @Test
    void runPartitionMaintenance_calls_pg_partman_run_maintenance_proc() {
        service.runPartitionMaintenance();

        verify(jdbcTemplate).execute("CALL partman.run_maintenance_proc()");
    }
}
