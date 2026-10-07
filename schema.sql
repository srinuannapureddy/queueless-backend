CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mobile VARCHAR(10) UNIQUE NOT NULL,
  name VARCHAR(80),
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS staff_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'staff',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS queues (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  state VARCHAR(100) NOT NULL,
  district VARCHAR(100) NOT NULL,
  department VARCHAR(100) NOT NULL,
  service VARCHAR(150) NOT NULL,
  prefix VARCHAR(10) NOT NULL,
  avg_service_minutes NUMERIC(6,2) NOT NULL DEFAULT 6,
  next_number INTEGER NOT NULL DEFAULT 1,
  current_number INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(state, district, department, service)
);

CREATE TABLE IF NOT EXISTS tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  queue_id UUID NOT NULL REFERENCES queues(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_number INTEGER NOT NULL,
  token_code VARCHAR(30) NOT NULL,
  name VARCHAR(80) NOT NULL,
  mobile VARCHAR(10) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'waiting',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tokens_queue_status_number
  ON tokens(queue_id, status, token_number);

CREATE INDEX IF NOT EXISTS idx_tokens_user_created
  ON tokens(user_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_token_per_user_queue
  ON tokens(user_id, queue_id)
  WHERE status IN ('waiting', 'serving', 'hold');

CREATE TABLE IF NOT EXISTS otp_audit (
  id BIGSERIAL PRIMARY KEY,
  mobile VARCHAR(10) NOT NULL,
  action VARCHAR(20) NOT NULL,
  status VARCHAR(30) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
