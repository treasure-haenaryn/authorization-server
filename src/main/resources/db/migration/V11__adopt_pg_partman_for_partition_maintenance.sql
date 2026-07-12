-- audit_logs/refresh_token_histories는 V4/V9에서 이미 파티션 테이블로 생성됐다.
-- 이후 관리(향후 파티션 사전 생성, 보존 기간 지난 파티션 자동 DROP)는 직접 코드를
-- 짜는 대신 pg_partman에 위임한다.
CREATE SCHEMA IF NOT EXISTS partman;
CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;

SELECT partman.create_parent(
    p_parent_table => 'public.audit_logs',
    p_control => 'occurred_at',
    p_interval => '1 month',
    p_premake => 2
);

UPDATE partman.part_config
SET retention = '365 days',
    retention_keep_table = false
WHERE parent_table = 'public.audit_logs';

SELECT partman.create_parent(
    p_parent_table => 'public.refresh_token_histories',
    p_control => 'occurred_at',
    p_interval => '1 month',
    p_premake => 2
);

UPDATE partman.part_config
SET retention = '90 days',
    retention_keep_table = false
WHERE parent_table = 'public.refresh_token_histories';
