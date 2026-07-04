-- Phase4: 로그인 실패 계정 잠금 시각 기록 (자동 잠금 해제 판단에 사용)
ALTER TABLE users ADD COLUMN account_locked_at TIMESTAMP;
