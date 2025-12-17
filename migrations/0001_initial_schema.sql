-- 로또 당첨 번호 데이터 테이블
CREATE TABLE IF NOT EXISTS lotto_draws (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  round_number INTEGER UNIQUE NOT NULL,
  draw_date TEXT NOT NULL,
  num1 INTEGER NOT NULL,
  num2 INTEGER NOT NULL,
  num3 INTEGER NOT NULL,
  num4 INTEGER NOT NULL,
  num5 INTEGER NOT NULL,
  num6 INTEGER NOT NULL,
  bonus INTEGER NOT NULL,
  total_prize TEXT,
  first_prize TEXT,
  first_winners INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  membership_type TEXT DEFAULT 'free' CHECK(membership_type IN ('free', 'premium', 'admin')),
  membership_expires_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- AI 예측 번호 테이블 (매주 생성)
CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  round_number INTEGER NOT NULL,
  set_index INTEGER NOT NULL,
  num1 INTEGER NOT NULL,
  num2 INTEGER NOT NULL,
  num3 INTEGER NOT NULL,
  num4 INTEGER NOT NULL,
  num5 INTEGER NOT NULL,
  num6 INTEGER NOT NULL,
  is_vip INTEGER DEFAULT 1,
  ai_comment TEXT,
  matched_count INTEGER DEFAULT 0,
  rank TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(round_number, set_index)
);

-- 결제 이력 테이블
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  order_id TEXT UNIQUE NOT NULL,
  amount INTEGER NOT NULL,
  payment_method TEXT,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'failed', 'refunded')),
  pg_tid TEXT,
  subscription_months INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 빈도 분석 캐시 테이블
CREATE TABLE IF NOT EXISTS frequency_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_round INTEGER NOT NULL,
  weeks_analyzed INTEGER NOT NULL,
  frequency_data TEXT NOT NULL,
  candidates TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(target_round, weeks_analyzed)
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_lotto_draws_round ON lotto_draws(round_number);
CREATE INDEX IF NOT EXISTS idx_lotto_draws_date ON lotto_draws(draw_date);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_predictions_round ON predictions(round_number);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
