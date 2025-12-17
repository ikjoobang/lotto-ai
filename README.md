# LOTTO AI - 후나츠 사카이 알고리즘 기반 로또 분석 서비스

## 프로젝트 개요

- **Name**: LOTTO AI
- **Goal**: 일본 로또 명인 '후나츠 사카이'의 분석 알고리즘과 Google Gemini AI를 결합하여 데이터 기반 로또 번호 추천
- **Features**: 
  - 후나츠 사카이 알고리즘 (빈출수 + 이월수 분석)
  - Gemini AI 연동 번호 추천
  - Freemium 회원제 (무료 1게임, 유료 5게임)
  - 월 정기결제 (KG이니시스)
  - 적중 결과 시각화

## URLs

- **개발 서버**: https://3000-iy710vwru6jljrzflk5nk-a402f90a.sandbox.novita.ai
- **프로덕션**: (Cloudflare Pages 배포 예정)

## 기술 스택

- **Backend**: Hono Framework (TypeScript)
- **Database**: Cloudflare D1 (SQLite)
- **AI**: Google Gemini API (gemini-1.5-flash)
- **Payment**: KG이니시스
- **Frontend**: Tailwind CSS + Chart.js
- **Deploy**: Cloudflare Pages

## API 엔드포인트

### Public
```
GET  /api/health                 - 서버 상태 확인
GET  /api/lotto/draws            - 로또 당첨번호 목록
GET  /api/lotto/draws/:round     - 특정 회차 당첨번호
GET  /api/lotto/analysis         - 후나츠 사카이 분석
GET  /api/predictions            - AI 예측 번호
GET  /api/predictions/history    - 과거 예측 기록
GET  /api/predictions/download   - TXT 다운로드
```

### Auth
```
POST /api/auth/register          - 회원가입
POST /api/auth/login             - 로그인
POST /api/auth/logout            - 로그아웃
GET  /api/auth/me                - 현재 사용자 정보
```

### Payment
```
POST /api/payment/init           - 결제 초기화
POST /api/payment/complete       - 결제 완료
```

### Admin
```
POST /api/admin/generate-predictions  - AI 예측 생성
POST /api/admin/update-results        - 적중 결과 업데이트
POST /api/admin/fetch-draws           - 동행복권 데이터 가져오기
```

## 데이터 아키텍처

### 데이터 모델
- **lotto_draws**: 로또 당첨번호 (회차, 번호, 보너스, 상금정보)
- **users**: 사용자 (이메일, 비밀번호, 멤버십)
- **predictions**: AI 예측 (회차, 번호 6개, 코멘트)
- **payments**: 결제 내역 (주문ID, 금액, 상태)
- **frequency_cache**: 분석 캐시

### 저장소
- **Cloudflare D1**: SQLite 기반 관계형 데이터베이스

## 후나츠 사카이 알고리즘

1. **분석 기간**: 최근 24주 (약 6개월)
2. **후보군 추출**: 3~4회 출현한 번호
3. **이월수 적용**: 직전 회차 번호 중 1~2개 포함
4. **AI 추론**: Gemini가 통계적 패턴 해석 후 최종 6개 선정

## 사용자 가이드

### 무료 회원
- 매주 1게임 AI 추천 번호 열람
- 기본 통계 분석 차트 확인

### 프리미엄 회원 (₩9,900/월)
- 매주 5게임 AI 추천 번호 열람
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
npm run dev:sandbox
```

## 배포

```bash
# 빌드
npm run build

# Cloudflare Pages 배포
npm run deploy
```

## 환경변수

```
GEMINI_API_KEY=your-gemini-api-key
JWT_SECRET=your-jwt-secret
INICIS_MID=your-merchant-id
INICIS_SIGN_KEY=your-sign-key
```

## 테스트 결과

전체 테스트 결과는 `TEST_RESULTS.txt` 파일을 참조하세요.

- **총 테스트 항목**: 58개
- **성공률**: 100%

## 주의사항

⚠️ 본 서비스는 참고용이며 당첨을 보장하지 않습니다.
📞 도박 중독 상담: 1336

## 라이선스

© 2024 LOTTO AI. All rights reserved.
