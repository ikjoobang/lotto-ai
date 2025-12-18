# LOTTO AI - 후나츠 사카이 알고리즘 기반 로또 분석 서비스

## 프로젝트 개요

- **Name**: LOTTO AI
- **Goal**: 일본 로또 명인 '후나츠 사카이'의 분석 알고리즘과 Google Gemini AI를 결합하여 데이터 기반 로또 번호 추천
- **Version**: 2.0 (Lead Generation Model)

## 비즈니스 모델 (v2.0)

### 회원 등급 시스템
| 등급 | 조건 | 주간 열람 한도 |
|------|------|----------------|
| **일반회원 (Basic)** | 회원가입 | 5게임/주 |
| **제휴회원 (Partner)** | 개인정보 제3자 제공 동의 | 20게임/주 |
| **관리자 (Admin)** | 시스템 관리자 | 무제한 |

### 리셋 스케줄
- **실행 시점**: 매주 일요일 오전 06:00 (KST)
- **동작**: 모든 회원의 `current_view_count`를 0으로 초기화

## URLs

- **프로덕션**: https://lotto-ai.pages.dev
- **개발 서버**: https://3000-xxx.sandbox.novita.ai

## 기술 스택

- **Backend**: Hono Framework (TypeScript)
- **Database**: Cloudflare D1 (SQLite)
- **AI**: Google Gemini API (gemini-1.5-flash)
- **Frontend**: Tailwind CSS + Chart.js
- **Deploy**: Cloudflare Pages

## API 엔드포인트

### Public
```
GET  /api/health                    - 서버 상태 확인
GET  /api/lotto/draws               - 로또 당첨번호 목록
GET  /api/lotto/draws/:round        - 특정 회차 당첨번호
GET  /api/lotto/analysis            - 후나츠 사카이 분석
GET  /api/predictions               - AI 예측 번호 (등급별 제한)
GET  /api/predictions/history       - 과거 예측 기록
GET  /api/predictions/download      - TXT 다운로드
```

### Auth
```
POST /api/auth/register             - 회원가입 (제3자 동의 포함)
POST /api/auth/login                - 로그인
POST /api/auth/logout               - 로그아웃
GET  /api/auth/me                   - 현재 사용자 정보
POST /api/auth/agree-partner        - 제휴회원 업그레이드
```

### Admin
```
POST /api/admin/generate-predictions - AI 예측 생성 (20게임)
POST /api/admin/update-results       - 적중 결과 업데이트
POST /api/admin/fetch-draws          - 동행복권 데이터 가져오기
POST /api/admin/weekly-reset         - 주간 열람 횟수 초기화
GET  /api/admin/leads                - 제휴회원 리드 목록
GET  /api/admin/leads/export         - 리드 CSV 추출 (김미경 지사장용)
GET  /api/admin/leads/stats          - 리드 통계
```

## 데이터 아키텍처

### 데이터 모델
- **lotto_draws**: 로또 당첨번호 (회차, 번호, 보너스, 상금정보)
- **users**: 사용자 (이메일, 비밀번호, 제3자동의, 주간열람한도/횟수)
- **predictions**: AI 예측 (회차, 번호 6개, 코멘트) - 20게임/주
- **partner_leads**: 제휴회원 리드 (이름, 연락처, 이메일, 동의일시, 추출여부)
- **frequency_cache**: 분석 캐시

### 저장소
- **Cloudflare D1**: SQLite 기반 관계형 데이터베이스

## 후나츠 사카이 알고리즘

1. **분석 기간**: 최근 24주 (약 6개월)
2. **후보군 추출**: 3~4회 출현한 번호
3. **이월수 적용**: 직전 회차 번호 중 1~2개 포함
4. **AI 추론**: Gemini가 통계적 패턴 해석 후 최종 선정

## 사용자 가이드

### 일반 회원
- 회원가입만으로 매주 5게임 AI 추천 번호 열람
- 기본 통계 분석 차트 확인

### 제휴 회원
- 개인정보 제3자 제공 동의 시 매주 20게임 열람
- 상세 AI 분석 코멘트
- TXT 파일 다운로드

## 로컬 개발

```bash
# 의존성 설치
npm install

# DB 마이그레이션
npm run db:migrate:local

# 시드 데이터 입력
npm run db:seed

# 개발 서버 시작
npm run build
pm2 start ecosystem.config.cjs
```

## 배포

```bash
# 빌드
npm run build

# 프로덕션 DB 마이그레이션
npm run db:migrate:prod

# Cloudflare Pages 배포
npm run deploy
```

## 환경변수

```
GEMINI_API_KEY=your-gemini-api-key
JWT_SECRET=your-jwt-secret
ADMIN_RESET_KEY=weekly-reset-secret-key
```

## 주간 리셋 Cron Job 설정

외부 서비스(예: Cloudflare Workers Cron Triggers, GitHub Actions)에서 매주 일요일 06:00에 호출:

```bash
curl -X POST https://lotto-ai.pages.dev/api/admin/weekly-reset \
  -H "X-Reset-Key: your-admin-reset-key"
```

## 법적 고지 (개인정보 제3자 제공)

회원가입 시 선택 동의 항목:
- **제공받는 자**: XIVIX 제휴서비스
- **제공 목적**: 로또 분석 서비스 안내, 보험/재무 설계 상담 및 마케팅 자료 활용
- **제공 항목**: 이름, 연락처, 이메일
- **보유 기간**: 동의 철회 시 또는 제공 목적 달성 시까지

## 주의사항

⚠️ 본 서비스는 참고용이며 당첨을 보장하지 않습니다.
📞 도박 중독 상담: 1336

## 라이선스

© 2024 LOTTO AI. All rights reserved.
