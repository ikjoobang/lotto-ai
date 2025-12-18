-- ============================================
-- LOTTO AI - DB 마케팅(Lead Generation) 모델 전환
-- 유료결제 → 제3자 정보제공 동의 기반 등급 시스템
-- ============================================

-- 사용자 테이블에 새 필드 추가
-- SQLite는 ALTER TABLE ADD COLUMN만 지원하므로 개별적으로 추가

-- 제3자 정보제공 동의 여부 (김미경 지사장 제공)
ALTER TABLE users ADD COLUMN agreed_to_third_party INTEGER DEFAULT 0;

-- 매주 열람 한도 (일반: 5, 제휴: 20)
ALTER TABLE users ADD COLUMN weekly_view_limit INTEGER DEFAULT 5;

-- 이번 주 열람 횟수
ALTER TABLE users ADD COLUMN current_view_count INTEGER DEFAULT 0;

-- 마지막 열람 리셋 일시
ALTER TABLE users ADD COLUMN last_reset_at TEXT;

-- 제3자 동의 일시
ALTER TABLE users ADD COLUMN agreed_at TEXT;

-- ============================================
-- 제휴 리드(Partner Leads) 테이블 - 김미경 지사장 제공용
-- ============================================
CREATE TABLE IF NOT EXISTS partner_leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT NOT NULL,
  agreed_at TEXT NOT NULL,
  exported INTEGER DEFAULT 0,
  exported_at TEXT,
  notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(user_id)
);

-- 인덱스 생성
CREATE INDEX IF NOT EXISTS idx_partner_leads_user ON partner_leads(user_id);
CREATE INDEX IF NOT EXISTS idx_partner_leads_exported ON partner_leads(exported);
CREATE INDEX IF NOT EXISTS idx_partner_leads_agreed_at ON partner_leads(agreed_at);
CREATE INDEX IF NOT EXISTS idx_users_agreed_third_party ON users(agreed_to_third_party);
