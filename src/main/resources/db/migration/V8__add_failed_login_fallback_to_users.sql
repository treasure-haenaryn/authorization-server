-- Phase5: Redis 장애 시 로그인 실패 카운트를 PostgreSQL로 폴백하기 위한 컬럼.
-- 평상시(Redis 정상)에는 이 컬럼들을 전혀 건드리지 않고 Redis 경로만 사용한다.
ALTER TABLE users ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN failed_login_window_started_at TIMESTAMP;

COMMENT ON COLUMN users.failed_login_count IS 'Redis 장애 시에만 증가하는 폴백 카운터 (정상 시 0 유지)';
COMMENT ON COLUMN users.failed_login_window_started_at IS '폴백 카운터의 윈도우 시작 시각. loginFailWindowHours 경과 시 카운터를 리셋하는 기준';
