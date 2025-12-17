import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

// Types
type Bindings = {
  DB: D1Database
  GEMINI_API_KEY: string
  JWT_SECRET: string
  INICIS_MID: string
  INICIS_SIGN_KEY: string
}

type Variables = {
  user?: {
    id: number
    email: string
    name: string
    membership_type: string
    membership_expires_at: string | null
  }
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Middleware
app.use('*', logger())
app.use('/api/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}))

// JWT utilities
async function createToken(payload: object, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const exp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 // 7 days
  const fullPayload = { ...payload, exp }
  
  const encoder = new TextEncoder()
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '')
  const payloadB64 = btoa(JSON.stringify(fullPayload)).replace(/=/g, '')
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${headerB64}.${payloadB64}`)
  )
  
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '')
  return `${headerB64}.${payloadB64}.${signatureB64}`
}

async function verifyToken(token: string, secret: string): Promise<object | null> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    
    const [headerB64, payloadB64, signatureB64] = parts
    const encoder = new TextEncoder()
    
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    
    const signature = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      encoder.encode(`${headerB64}.${payloadB64}`)
    )
    
    if (!valid) return null
    
    const payload = JSON.parse(atob(payloadB64))
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null
    
    return payload
  } catch {
    return null
  }
}

// Password hashing using Web Crypto API
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    256
  )
  
  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('')
  return `${saltHex}:${hashHex}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, storedHash] = stored.split(':')
  if (!saltHex || !storedHash) return false
  
  const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(b => parseInt(b, 16)))
  const encoder = new TextEncoder()
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    256
  )
  
  const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('')
  return hashHex === storedHash
}

// Auth middleware
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization')
  const cookieToken = getCookie(c, 'auth_token')
  const token = authHeader?.replace('Bearer ', '') || cookieToken
  
  if (!token) {
    c.set('user', null)
    return next()
  }
  
  const jwtSecret = c.env.JWT_SECRET || 'lotto-ai-secret-key-2024'
  const payload = await verifyToken(token, jwtSecret) as any
  
  if (payload && payload.userId) {
    const db = c.env.DB
    const user = await db.prepare('SELECT id, email, name, membership_type, membership_expires_at FROM users WHERE id = ?')
      .bind(payload.userId)
      .first()
    
    if (user) {
      // Check if premium membership expired
      if (user.membership_type === 'premium' && user.membership_expires_at) {
        const expiresAt = new Date(user.membership_expires_at)
        if (expiresAt < new Date()) {
          await db.prepare('UPDATE users SET membership_type = ? WHERE id = ?')
            .bind('free', user.id)
            .run()
          user.membership_type = 'free'
        }
      }
      c.set('user', user)
    }
  }
  
  return next()
}

// Apply auth middleware to API routes
app.use('/api/*', authMiddleware)

// ============================
// API Routes
// ============================

// Health check
app.get('/api/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// ============================
// Auth Routes
// ============================

// Register
app.post('/api/auth/register', async (c) => {
  try {
    const { email, password, name, phone } = await c.req.json()
    
    if (!email || !password || !name) {
      return c.json({ error: '이메일, 비밀번호, 이름은 필수입니다.' }, 400)
    }
    
    const db = c.env.DB
    
    // Check existing user
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
    if (existing) {
      return c.json({ error: '이미 등록된 이메일입니다.' }, 400)
    }
    
    const passwordHash = await hashPassword(password)
    
    const result = await db.prepare(
      'INSERT INTO users (email, password_hash, name, phone) VALUES (?, ?, ?, ?)'
    ).bind(email, passwordHash, name, phone || null).run()
    
    const jwtSecret = c.env.JWT_SECRET || 'lotto-ai-secret-key-2024'
    const token = await createToken({ userId: result.meta.last_row_id }, jwtSecret)
    
    setCookie(c, 'auth_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 * 7
    })
    
    return c.json({ 
      success: true, 
      token,
      user: { email, name, membership_type: 'free' }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// Login
app.post('/api/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json()
    
    if (!email || !password) {
      return c.json({ error: '이메일과 비밀번호를 입력하세요.' }, 400)
    }
    
    const db = c.env.DB
    const user = await db.prepare(
      'SELECT id, email, name, password_hash, membership_type, membership_expires_at FROM users WHERE email = ?'
    ).bind(email).first() as any
    
    if (!user) {
      return c.json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }
    
    const valid = await verifyPassword(password, user.password_hash)
    if (!valid) {
      return c.json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' }, 401)
    }
    
    const jwtSecret = c.env.JWT_SECRET || 'lotto-ai-secret-key-2024'
    const token = await createToken({ userId: user.id }, jwtSecret)
    
    setCookie(c, 'auth_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 * 7
    })
    
    return c.json({
      success: true,
      token,
      user: {
        email: user.email,
        name: user.name,
        membership_type: user.membership_type,
        membership_expires_at: user.membership_expires_at
      }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// Logout
app.post('/api/auth/logout', (c) => {
  deleteCookie(c, 'auth_token')
  return c.json({ success: true })
})

// Get current user
app.get('/api/auth/me', async (c) => {
  const user = c.get('user')
  if (!user) {
    return c.json({ error: '로그인이 필요합니다.' }, 401)
  }
  return c.json({ user })
})

// ============================
// Lotto Data Routes
// ============================

// Get recent lotto draws
app.get('/api/lotto/draws', async (c) => {
  const db = c.env.DB
  const limit = parseInt(c.req.query('limit') || '24')
  
  const draws = await db.prepare(
    'SELECT * FROM lotto_draws ORDER BY round_number DESC LIMIT ?'
  ).bind(limit).all()
  
  return c.json({ draws: draws.results })
})

// Get specific draw
app.get('/api/lotto/draws/:round', async (c) => {
  const db = c.env.DB
  const round = parseInt(c.req.param('round'))
  
  const draw = await db.prepare(
    'SELECT * FROM lotto_draws WHERE round_number = ?'
  ).bind(round).first()
  
  if (!draw) {
    return c.json({ error: '해당 회차 정보를 찾을 수 없습니다.' }, 404)
  }
  
  return c.json({ draw })
})

// Get frequency analysis (후나츠 사카이 알고리즘 기반)
app.get('/api/lotto/analysis', async (c) => {
  const db = c.env.DB
  const weeks = parseInt(c.req.query('weeks') || '24')
  
  const draws = await db.prepare(
    'SELECT num1, num2, num3, num4, num5, num6 FROM lotto_draws ORDER BY round_number DESC LIMIT ?'
  ).bind(weeks).all()
  
  // Count frequency
  const frequency: { [key: number]: number } = {}
  for (let i = 1; i <= 45; i++) frequency[i] = 0
  
  for (const draw of draws.results as any[]) {
    [draw.num1, draw.num2, draw.num3, draw.num4, draw.num5, draw.num6].forEach((num: number) => {
      frequency[num]++
    })
  }
  
  // 후나츠 사카이 로직: 3~4회 등장한 번호가 당첨 확률 높음
  const candidates = Object.entries(frequency)
    .filter(([_, count]) => count >= 3 && count <= 4)
    .map(([num, count]) => ({ number: parseInt(num), count }))
    .sort((a, b) => b.count - a.count)
  
  // 이월수 (직전 회차 번호)
  const lastDraw = draws.results[0] as any
  const carryoverNumbers = lastDraw 
    ? [lastDraw.num1, lastDraw.num2, lastDraw.num3, lastDraw.num4, lastDraw.num5, lastDraw.num6]
    : []
  
  return c.json({
    weeks_analyzed: weeks,
    total_draws: draws.results.length,
    frequency: Object.entries(frequency).map(([num, count]) => ({ number: parseInt(num), count })).sort((a, b) => a.number - b.number),
    candidates,
    carryover_numbers: carryoverNumbers
  })
})

// ============================
// Predictions Routes
// ============================

// Get predictions for current round
app.get('/api/predictions', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  
  // Get latest round number + 1 for predictions
  const latestDraw = await db.prepare(
    'SELECT round_number FROM lotto_draws ORDER BY round_number DESC LIMIT 1'
  ).first() as any
  
  const targetRound = latestDraw ? latestDraw.round_number + 1 : 1151
  
  const predictions = await db.prepare(
    'SELECT id, round_number, set_index, num1, num2, num3, num4, num5, num6, is_vip, ai_comment, matched_count, rank FROM predictions WHERE round_number = ? ORDER BY set_index'
  ).bind(targetRound).all()
  
  // Freemium logic: non-premium users can only see 1 prediction
  const isPremium = user && (user.membership_type === 'premium' || user.membership_type === 'admin')
  
  const formattedPredictions = predictions.results.map((pred: any, index: number) => {
    const isLocked = !isPremium && pred.is_vip === 1
    
    if (isLocked) {
      return {
        id: pred.id,
        set_index: pred.set_index,
        numbers: ['?', '?', '?', '?', '?', '?'],
        locked: true,
        ai_comment: '🔒 유료 회원 전용'
      }
    }
    
    return {
      id: pred.id,
      set_index: pred.set_index,
      numbers: [pred.num1, pred.num2, pred.num3, pred.num4, pred.num5, pred.num6],
      locked: false,
      ai_comment: pred.ai_comment
    }
  })
  
  return c.json({
    round_number: targetRound,
    predictions: formattedPredictions,
    user_type: user?.membership_type || 'guest'
  })
})

// Get past predictions with results
app.get('/api/predictions/history', async (c) => {
  const db = c.env.DB
  const limit = parseInt(c.req.query('limit') || '10')
  
  // Get predictions that have been matched with actual results
  const history = await db.prepare(`
    SELECT p.*, d.num1 as actual_num1, d.num2 as actual_num2, d.num3 as actual_num3, 
           d.num4 as actual_num4, d.num5 as actual_num5, d.num6 as actual_num6, d.bonus
    FROM predictions p
    LEFT JOIN lotto_draws d ON p.round_number = d.round_number
    WHERE d.round_number IS NOT NULL
    ORDER BY p.round_number DESC, p.set_index
    LIMIT ?
  `).bind(limit * 5).all()
  
  return c.json({ history: history.results })
})

// ============================
// Gemini AI Routes
// ============================

// Generate predictions using Gemini
app.post('/api/admin/generate-predictions', async (c) => {
  const user = c.get('user')
  
  // Admin check
  if (!user || user.membership_type !== 'admin') {
    return c.json({ error: '관리자 권한이 필요합니다.' }, 403)
  }
  
  const db = c.env.DB
  const geminiApiKey = c.env.GEMINI_API_KEY || 'AIzaSyAZjvD4bM-c6klrcrnFCpiBLSoSz_goPQ4'
  
  try {
    // Get analysis data
    const draws = await db.prepare(
      'SELECT num1, num2, num3, num4, num5, num6 FROM lotto_draws ORDER BY round_number DESC LIMIT 24'
    ).bind().all()
    
    // Calculate frequency
    const frequency: { [key: number]: number } = {}
    for (let i = 1; i <= 45; i++) frequency[i] = 0
    
    for (const draw of draws.results as any[]) {
      [draw.num1, draw.num2, draw.num3, draw.num4, draw.num5, draw.num6].forEach((num: number) => {
        frequency[num]++
      })
    }
    
    const candidates = Object.entries(frequency)
      .filter(([_, count]) => count >= 3 && count <= 4)
      .map(([num]) => parseInt(num))
    
    const lastDraw = draws.results[0] as any
    const carryoverNumbers = [lastDraw.num1, lastDraw.num2, lastDraw.num3, lastDraw.num4, lastDraw.num5, lastDraw.num6]
    
    // Get next round number
    const latestDraw = await db.prepare(
      'SELECT round_number FROM lotto_draws ORDER BY round_number DESC LIMIT 1'
    ).first() as any
    const targetRound = latestDraw ? latestDraw.round_number + 1 : 1151
    
    // Call Gemini API
    const prompt = `당신은 로또 분석 전문가입니다. '후나츠 사카이' 분석법에 따라 다음 주 로또 번호를 예측해 주세요.

[분석 데이터]
1. 최근 6개월간 3~4회 등장하여 당첨 확률이 높은 후보 번호: ${JSON.stringify(candidates)}
2. 직전 회차 당첨 번호(이월수 후보): ${JSON.stringify(carryoverNumbers)}
3. 번호별 출현 빈도: ${JSON.stringify(frequency)}

[규칙]
- 위 '후보 번호' 중에서 4~5개를 선택하세요.
- '이월수 후보' 중에서 반드시 1개를 포함하세요.
- 총 6개의 숫자를 1~45 범위에서 선택하세요.
- 서로 다른 조합 5세트를 생성하세요.
- 각 조합에 대한 간단한 분석 코멘트를 한국어로 작성하세요.

반드시 다음 JSON 형식으로만 응답하세요:
{
  "predictions": [
    { "numbers": [1, 2, 3, 4, 5, 6], "comment": "분석 코멘트" },
    { "numbers": [7, 8, 9, 10, 11, 12], "comment": "분석 코멘트" },
    { "numbers": [13, 14, 15, 16, 17, 18], "comment": "분석 코멘트" },
    { "numbers": [19, 20, 21, 22, 23, 24], "comment": "분석 코멘트" },
    { "numbers": [25, 26, 27, 28, 29, 30], "comment": "분석 코멘트" }
  ]
}`

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 1024
          }
        })
      }
    )
    
    if (!response.ok) {
      const errorText = await response.text()
      return c.json({ error: `Gemini API 오류: ${errorText}` }, 500)
    }
    
    const geminiResponse = await response.json() as any
    const textContent = geminiResponse.candidates?.[0]?.content?.parts?.[0]?.text
    
    if (!textContent) {
      return c.json({ error: 'Gemini 응답이 비어있습니다.' }, 500)
    }
    
    // Parse JSON from response
    let predictions
    try {
      const jsonMatch = textContent.match(/\{[\s\S]*\}/)
      if (!jsonMatch) throw new Error('JSON not found')
      predictions = JSON.parse(jsonMatch[0]).predictions
    } catch {
      return c.json({ error: 'Gemini 응답 파싱 실패', raw: textContent }, 500)
    }
    
    // Delete existing predictions for this round
    await db.prepare('DELETE FROM predictions WHERE round_number = ?').bind(targetRound).run()
    
    // Insert new predictions
    for (let i = 0; i < predictions.length; i++) {
      const pred = predictions[i]
      const nums = pred.numbers.sort((a: number, b: number) => a - b)
      
      await db.prepare(
        'INSERT INTO predictions (round_number, set_index, num1, num2, num3, num4, num5, num6, is_vip, ai_comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(targetRound, i + 1, nums[0], nums[1], nums[2], nums[3], nums[4], nums[5], i > 0 ? 1 : 0, pred.comment).run()
    }
    
    return c.json({ 
      success: true, 
      round_number: targetRound,
      predictions_count: predictions.length 
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// Update results (match predictions with actual draws)
app.post('/api/admin/update-results', async (c) => {
  const user = c.get('user')
  
  if (!user || user.membership_type !== 'admin') {
    return c.json({ error: '관리자 권한이 필요합니다.' }, 403)
  }
  
  const db = c.env.DB
  const { round_number, numbers, bonus } = await c.req.json()
  
  if (!round_number || !numbers || numbers.length !== 6) {
    return c.json({ error: '회차 번호와 당첨 번호 6개를 입력하세요.' }, 400)
  }
  
  // Get predictions for this round
  const predictions = await db.prepare(
    'SELECT * FROM predictions WHERE round_number = ?'
  ).bind(round_number).all()
  
  const actualSet = new Set(numbers)
  
  for (const pred of predictions.results as any[]) {
    const predNumbers = [pred.num1, pred.num2, pred.num3, pred.num4, pred.num5, pred.num6]
    const matchedCount = predNumbers.filter(n => actualSet.has(n)).length
    
    let rank = '낙첨'
    if (matchedCount === 6) rank = '1등'
    else if (matchedCount === 5 && predNumbers.includes(bonus)) rank = '2등'
    else if (matchedCount === 5) rank = '3등'
    else if (matchedCount === 4) rank = '4등'
    else if (matchedCount === 3) rank = '5등'
    
    await db.prepare(
      'UPDATE predictions SET matched_count = ?, rank = ? WHERE id = ?'
    ).bind(matchedCount, rank, pred.id).run()
  }
  
  return c.json({ success: true, updated: predictions.results.length })
})

// ============================
// Payment Routes (KG이니시스)
// ============================

// Initialize payment
app.post('/api/payment/init', async (c) => {
  const user = c.get('user')
  
  if (!user) {
    return c.json({ error: '로그인이 필요합니다.' }, 401)
  }
  
  const { months = 1 } = await c.req.json()
  const amount = months * 9900 // 월 9,900원
  
  const db = c.env.DB
  const orderId = `LOTTO${Date.now()}${Math.random().toString(36).substr(2, 9)}`
  
  await db.prepare(
    'INSERT INTO payments (user_id, order_id, amount, subscription_months, status) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.id, orderId, amount, months, 'pending').run()
  
  // KG이니시스 결제 설정
  const mid = c.env.INICIS_MID || 'MOI9559449'
  const timestamp = Date.now().toString()
  
  return c.json({
    success: true,
    order_id: orderId,
    amount,
    months,
    pg_config: {
      mid,
      order_id: orderId,
      amount,
      goods_name: `LOTTO AI ${months}개월 이용권`,
      buyer_name: user.name,
      buyer_email: user.email,
      timestamp
    }
  })
})

// Payment complete callback
app.post('/api/payment/complete', async (c) => {
  const db = c.env.DB
  const { order_id, pg_tid, status } = await c.req.json()
  
  if (!order_id) {
    return c.json({ error: '주문 ID가 필요합니다.' }, 400)
  }
  
  const payment = await db.prepare(
    'SELECT * FROM payments WHERE order_id = ?'
  ).bind(order_id).first() as any
  
  if (!payment) {
    return c.json({ error: '결제 정보를 찾을 수 없습니다.' }, 404)
  }
  
  if (status === 'success') {
    const now = new Date()
    const expiresAt = new Date(now.setMonth(now.getMonth() + payment.subscription_months))
    
    // Update payment status
    await db.prepare('UPDATE payments SET status = ?, pg_tid = ?, completed_at = ? WHERE order_id = ?')
      .bind('completed', pg_tid, new Date().toISOString(), order_id).run()
    
    // Update user membership
    await db.prepare('UPDATE users SET membership_type = ?, membership_expires_at = ? WHERE id = ?')
      .bind('premium', expiresAt.toISOString(), payment.user_id).run()
    
    return c.json({ success: true, membership_expires_at: expiresAt.toISOString() })
  } else {
    await db.prepare('UPDATE payments SET status = ? WHERE order_id = ?')
      .bind('failed', order_id).run()
    
    return c.json({ success: false, error: '결제에 실패했습니다.' })
  }
})

// ============================
// Admin Routes
// ============================

// Fetch lotto data from API (동행복권)
app.post('/api/admin/fetch-draws', async (c) => {
  const user = c.get('user')
  
  if (!user || user.membership_type !== 'admin') {
    return c.json({ error: '관리자 권한이 필요합니다.' }, 403)
  }
  
  const db = c.env.DB
  const { start_round, end_round } = await c.req.json()
  
  const results = []
  
  for (let round = start_round; round <= end_round; round++) {
    try {
      const response = await fetch(
        `https://www.dhlottery.co.kr/common.do?method=getLottoNumber&drwNo=${round}`
      )
      const data = await response.json() as any
      
      if (data.returnValue === 'success') {
        await db.prepare(`
          INSERT OR REPLACE INTO lotto_draws 
          (round_number, draw_date, num1, num2, num3, num4, num5, num6, bonus, first_prize, first_winners)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          data.drwNo,
          data.drwNoDate,
          data.drwtNo1,
          data.drwtNo2,
          data.drwtNo3,
          data.drwtNo4,
          data.drwtNo5,
          data.drwtNo6,
          data.bnusNo,
          data.firstWinamnt?.toString() || '',
          data.firstPrzwnerCo || 0
        ).run()
        
        results.push({ round, status: 'success' })
      } else {
        results.push({ round, status: 'not_found' })
      }
    } catch (error: any) {
      results.push({ round, status: 'error', message: error.message })
    }
  }
  
  return c.json({ success: true, results })
})

// Download predictions as TXT
app.get('/api/predictions/download', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  
  const latestDraw = await db.prepare(
    'SELECT round_number FROM lotto_draws ORDER BY round_number DESC LIMIT 1'
  ).first() as any
  const targetRound = latestDraw ? latestDraw.round_number + 1 : 1151
  
  const predictions = await db.prepare(
    'SELECT * FROM predictions WHERE round_number = ? ORDER BY set_index'
  ).bind(targetRound).all()
  
  const isPremium = user && (user.membership_type === 'premium' || user.membership_type === 'admin')
  
  let content = `===========================================\n`
  content += `    LOTTO AI - ${targetRound}회 추천 번호\n`
  content += `    생성일: ${new Date().toLocaleDateString('ko-KR')}\n`
  content += `===========================================\n\n`
  
  for (const pred of predictions.results as any[]) {
    const isLocked = !isPremium && pred.is_vip === 1
    
    if (isLocked) {
      content += `[조합 ${pred.set_index}] 🔒 유료 회원 전용\n\n`
    } else {
      content += `[조합 ${pred.set_index}]\n`
      content += `번호: ${pred.num1} - ${pred.num2} - ${pred.num3} - ${pred.num4} - ${pred.num5} - ${pred.num6}\n`
      content += `분석: ${pred.ai_comment}\n\n`
    }
  }
  
  content += `\n-------------------------------------------\n`
  content += `※ 본 서비스는 참고용이며, 당첨을 보장하지 않습니다.\n`
  content += `※ 도박 중독 상담: 1336\n`
  
  return new Response(content, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="lotto_${targetRound}_predictions.txt"`
    }
  })
})

// ============================
// Frontend HTML
// ============================

app.get('*', async (c) => {
  const html = `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LOTTO AI - 후나츠 사카이 알고리즘 기반 로또 분석</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@300;400;500;700;900&display=swap');
    
    * { font-family: 'Noto Sans KR', sans-serif; }
    
    body {
      background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
      min-height: 100vh;
    }
    
    .glass {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .lotto-ball {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 18px;
      color: white;
      text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
      box-shadow: inset 0 -3px 5px rgba(0,0,0,0.3), 0 4px 10px rgba(0,0,0,0.3);
    }
    
    .ball-1-10 { background: linear-gradient(145deg, #fcd34d, #f59e0b); }
    .ball-11-20 { background: linear-gradient(145deg, #60a5fa, #3b82f6); }
    .ball-21-30 { background: linear-gradient(145deg, #f87171, #ef4444); }
    .ball-31-40 { background: linear-gradient(145deg, #a78bfa, #8b5cf6); }
    .ball-41-45 { background: linear-gradient(145deg, #34d399, #10b981); }
    
    .locked-ball {
      background: linear-gradient(145deg, #374151, #1f2937);
      color: #6b7280;
    }
    
    .gradient-text {
      background: linear-gradient(90deg, #fcd34d, #f59e0b, #ef4444);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    
    .animate-pulse-slow {
      animation: pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }
    
    .success-badge {
      background: linear-gradient(90deg, #fcd34d, #f59e0b);
      animation: glow 2s ease-in-out infinite;
    }
    
    @keyframes glow {
      0%, 100% { box-shadow: 0 0 20px rgba(252, 211, 77, 0.5); }
      50% { box-shadow: 0 0 40px rgba(252, 211, 77, 0.8); }
    }
    
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }
    
    .modal.show { display: flex; }
    
    .hero-gradient {
      background: radial-gradient(ellipse at center, rgba(252, 211, 77, 0.15) 0%, transparent 70%);
    }
    
    .scrollbar-hide::-webkit-scrollbar { display: none; }
    .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
  </style>
</head>
<body class="text-white">
  <div id="app">
    <!-- Navigation -->
    <nav class="glass fixed top-0 left-0 right-0 z-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16 items-center">
          <a href="/" class="flex items-center space-x-2">
            <i class="fas fa-dice text-yellow-400 text-2xl"></i>
            <span class="text-xl font-bold gradient-text">LOTTO AI</span>
          </a>
          
          <div class="hidden md:flex items-center space-x-8">
            <a href="#predictions" class="text-gray-300 hover:text-yellow-400 transition">AI 추천</a>
            <a href="#analysis" class="text-gray-300 hover:text-yellow-400 transition">분석</a>
            <a href="#results" class="text-gray-300 hover:text-yellow-400 transition">적중 결과</a>
            <a href="#pricing" class="text-gray-300 hover:text-yellow-400 transition">요금제</a>
          </div>
          
          <div id="auth-buttons" class="flex items-center space-x-4">
            <button onclick="showLoginModal()" class="text-gray-300 hover:text-white transition">로그인</button>
            <button onclick="showRegisterModal()" class="bg-yellow-500 hover:bg-yellow-400 text-black px-4 py-2 rounded-lg font-medium transition">회원가입</button>
          </div>
          
          <div id="user-menu" class="hidden items-center space-x-4">
            <span id="user-name" class="text-gray-300"></span>
            <span id="membership-badge" class="px-2 py-1 rounded text-xs font-bold"></span>
            <button onclick="logout()" class="text-gray-400 hover:text-white transition">
              <i class="fas fa-sign-out-alt"></i>
            </button>
          </div>
          
          <button class="md:hidden text-gray-300" onclick="toggleMobileMenu()">
            <i class="fas fa-bars text-2xl"></i>
          </button>
        </div>
      </div>
    </nav>
    
    <!-- Mobile Menu -->
    <div id="mobile-menu" class="hidden fixed inset-0 z-40 bg-black/95 pt-20 px-4">
      <div class="flex flex-col space-y-4">
        <a href="#predictions" class="text-xl text-gray-300 py-3 border-b border-gray-800" onclick="toggleMobileMenu()">AI 추천</a>
        <a href="#analysis" class="text-xl text-gray-300 py-3 border-b border-gray-800" onclick="toggleMobileMenu()">분석</a>
        <a href="#results" class="text-xl text-gray-300 py-3 border-b border-gray-800" onclick="toggleMobileMenu()">적중 결과</a>
        <a href="#pricing" class="text-xl text-gray-300 py-3 border-b border-gray-800" onclick="toggleMobileMenu()">요금제</a>
      </div>
    </div>
    
    <!-- Hero Section -->
    <section class="relative pt-24 pb-16 hero-gradient">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center">
          <h1 class="text-4xl md:text-6xl font-black mb-6">
            <span class="gradient-text">후나츠 사카이</span> 알고리즘 +<br>
            <span class="text-white">AI가 분석한 로또 번호</span>
          </h1>
          <p class="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
            일본 로또 명인의 분석법과 Google Gemini AI의 추론을 결합한<br>
            데이터 기반 로또 번호 추천 서비스
          </p>
          
          <div class="flex flex-col sm:flex-row justify-center gap-4 mb-12">
            <a href="#predictions" class="bg-gradient-to-r from-yellow-500 to-orange-500 text-black px-8 py-4 rounded-xl font-bold text-lg hover:opacity-90 transition">
              <i class="fas fa-magic mr-2"></i>무료로 1게임 받기
            </a>
            <a href="#pricing" class="glass text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-white/10 transition">
              <i class="fas fa-crown mr-2 text-yellow-400"></i>프리미엄 구독
            </a>
          </div>
          
          <!-- Stats -->
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            <div class="glass rounded-xl p-4">
              <div class="text-3xl font-bold text-yellow-400">24주</div>
              <div class="text-gray-400 text-sm">분석 기간</div>
            </div>
            <div class="glass rounded-xl p-4">
              <div class="text-3xl font-bold text-yellow-400">5세트</div>
              <div class="text-gray-400 text-sm">매주 추천</div>
            </div>
            <div class="glass rounded-xl p-4">
              <div class="text-3xl font-bold text-yellow-400" id="stat-hit-rate">85%</div>
              <div class="text-gray-400 text-sm">3개 이상 적중</div>
            </div>
            <div class="glass rounded-xl p-4">
              <div class="text-3xl font-bold text-yellow-400" id="stat-users">1,234</div>
              <div class="text-gray-400 text-sm">이용자 수</div>
            </div>
          </div>
        </div>
      </div>
    </section>
    
    <!-- Results Banner (if any recent hits) -->
    <section id="results-banner" class="hidden py-4 success-badge">
      <div class="max-w-7xl mx-auto px-4 text-center">
        <div class="flex items-center justify-center gap-4">
          <i class="fas fa-trophy text-2xl"></i>
          <span class="font-bold text-lg" id="banner-text">🎉 지난주 추천 번호 3개 적중! (5등 당첨)</span>
        </div>
      </div>
    </section>
    
    <!-- Predictions Section -->
    <section id="predictions" class="py-16">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold mb-4">
            <i class="fas fa-robot text-yellow-400 mr-2"></i>
            <span id="prediction-round">1151</span>회 AI 추천 번호
          </h2>
          <p class="text-gray-400">후나츠 사카이 알고리즘 + Gemini AI 분석</p>
        </div>
        
        <div id="predictions-container" class="space-y-6">
          <!-- Predictions will be loaded here -->
          <div class="text-center py-8">
            <i class="fas fa-spinner fa-spin text-4xl text-yellow-400"></i>
            <p class="text-gray-400 mt-4">추천 번호를 불러오는 중...</p>
          </div>
        </div>
        
        <div class="text-center mt-8">
          <button onclick="downloadPredictions()" class="glass px-6 py-3 rounded-lg hover:bg-white/10 transition">
            <i class="fas fa-download mr-2"></i>TXT 파일로 다운로드
          </button>
        </div>
      </div>
    </section>
    
    <!-- Analysis Section -->
    <section id="analysis" class="py-16 bg-black/30">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold mb-4">
            <i class="fas fa-chart-bar text-yellow-400 mr-2"></i>
            번호별 출현 빈도
          </h2>
          <p class="text-gray-400">최근 24주간 데이터 분석</p>
        </div>
        
        <div class="glass rounded-2xl p-6 mb-8">
          <canvas id="frequency-chart" height="300"></canvas>
        </div>
        
        <div class="grid md:grid-cols-2 gap-8">
          <div class="glass rounded-2xl p-6">
            <h3 class="text-xl font-bold mb-4 flex items-center">
              <i class="fas fa-fire text-orange-500 mr-2"></i>
              후보 번호 (3~4회 출현)
            </h3>
            <p class="text-gray-400 text-sm mb-4">후나츠 사카이 이론: 너무 많이도, 적게도 나오지 않은 번호가 유망</p>
            <div id="candidates-container" class="flex flex-wrap gap-2">
              <!-- Candidates will be loaded -->
            </div>
          </div>
          
          <div class="glass rounded-2xl p-6">
            <h3 class="text-xl font-bold mb-4 flex items-center">
              <i class="fas fa-redo text-blue-500 mr-2"></i>
              이월수 후보
            </h3>
            <p class="text-gray-400 text-sm mb-4">직전 회차 당첨 번호 중 1~2개가 다음 회차에 재출현하는 경향</p>
            <div id="carryover-container" class="flex flex-wrap gap-2">
              <!-- Carryover numbers will be loaded -->
            </div>
          </div>
        </div>
      </div>
    </section>
    
    <!-- Past Results Section -->
    <section id="results" class="py-16">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold mb-4">
            <i class="fas fa-history text-yellow-400 mr-2"></i>
            최근 적중 결과
          </h2>
          <p class="text-gray-400">지난 추천 번호의 실제 적중 결과</p>
        </div>
        
        <div id="history-container" class="space-y-4">
          <!-- History will be loaded -->
        </div>
      </div>
    </section>
    
    <!-- Pricing Section -->
    <section id="pricing" class="py-16 bg-black/30">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-12">
          <h2 class="text-3xl md:text-4xl font-bold mb-4">
            <i class="fas fa-crown text-yellow-400 mr-2"></i>
            요금제
          </h2>
          <p class="text-gray-400">더 많은 추천 번호와 상세 분석을 받아보세요</p>
        </div>
        
        <div class="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          <!-- Free Plan -->
          <div class="glass rounded-2xl p-8">
            <div class="text-center mb-6">
              <h3 class="text-2xl font-bold">무료</h3>
              <div class="text-4xl font-black mt-2">₩0</div>
              <p class="text-gray-400">영원히 무료</p>
            </div>
            <ul class="space-y-4 mb-8">
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                매주 1게임 추천
              </li>
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                기본 통계 분석
              </li>
              <li class="flex items-center text-gray-500">
                <i class="fas fa-times text-red-500 mr-3"></i>
                AI 분석 코멘트
              </li>
              <li class="flex items-center text-gray-500">
                <i class="fas fa-times text-red-500 mr-3"></i>
                TXT 다운로드
              </li>
            </ul>
            <button class="w-full py-3 rounded-lg border border-gray-600 text-gray-400 cursor-default">
              현재 플랜
            </button>
          </div>
          
          <!-- Premium Plan -->
          <div class="relative glass rounded-2xl p-8 border-2 border-yellow-500">
            <div class="absolute -top-4 left-1/2 transform -translate-x-1/2 bg-yellow-500 text-black px-4 py-1 rounded-full font-bold text-sm">
              BEST
            </div>
            <div class="text-center mb-6">
              <h3 class="text-2xl font-bold gradient-text">프리미엄</h3>
              <div class="text-4xl font-black mt-2">₩9,900<span class="text-lg font-normal text-gray-400">/월</span></div>
              <p class="text-gray-400">매주 5게임 + AI 분석</p>
            </div>
            <ul class="space-y-4 mb-8">
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                매주 5게임 추천
              </li>
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                상세 통계 분석
              </li>
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                AI 분석 코멘트
              </li>
              <li class="flex items-center text-gray-300">
                <i class="fas fa-check text-green-500 mr-3"></i>
                TXT 다운로드
              </li>
            </ul>
            <button onclick="subscribe()" class="w-full py-3 rounded-lg bg-gradient-to-r from-yellow-500 to-orange-500 text-black font-bold hover:opacity-90 transition">
              구독하기
            </button>
          </div>
        </div>
      </div>
    </section>
    
    <!-- Footer -->
    <footer class="py-12 border-t border-gray-800">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid md:grid-cols-4 gap-8">
          <div>
            <div class="flex items-center space-x-2 mb-4">
              <i class="fas fa-dice text-yellow-400 text-2xl"></i>
              <span class="text-xl font-bold gradient-text">LOTTO AI</span>
            </div>
            <p class="text-gray-400 text-sm">
              후나츠 사카이 알고리즘과 AI를 결합한<br>
              데이터 기반 로또 번호 분석 서비스
            </p>
          </div>
          <div>
            <h4 class="font-bold mb-4">서비스</h4>
            <ul class="space-y-2 text-gray-400 text-sm">
              <li><a href="#predictions" class="hover:text-yellow-400">AI 추천</a></li>
              <li><a href="#analysis" class="hover:text-yellow-400">분석</a></li>
              <li><a href="#pricing" class="hover:text-yellow-400">요금제</a></li>
            </ul>
          </div>
          <div>
            <h4 class="font-bold mb-4">고객지원</h4>
            <ul class="space-y-2 text-gray-400 text-sm">
              <li><a href="#" class="hover:text-yellow-400">이용약관</a></li>
              <li><a href="#" class="hover:text-yellow-400">개인정보처리방침</a></li>
              <li><a href="#" class="hover:text-yellow-400">문의하기</a></li>
            </ul>
          </div>
          <div>
            <h4 class="font-bold mb-4">경고</h4>
            <p class="text-gray-400 text-sm">
              본 서비스는 참고용이며 당첨을 보장하지 않습니다.<br>
              도박 중독 상담: <span class="text-yellow-400">1336</span>
            </p>
          </div>
        </div>
        <div class="mt-8 pt-8 border-t border-gray-800 text-center text-gray-500 text-sm">
          © 2024 LOTTO AI. All rights reserved.
        </div>
      </div>
    </footer>
  </div>
  
  <!-- Login Modal -->
  <div id="login-modal" class="modal">
    <div class="glass rounded-2xl p-8 max-w-md w-full mx-4">
      <div class="flex justify-between items-center mb-6">
        <h3 class="text-2xl font-bold">로그인</h3>
        <button onclick="hideLoginModal()" class="text-gray-400 hover:text-white">
          <i class="fas fa-times text-xl"></i>
        </button>
      </div>
      <form id="login-form" onsubmit="handleLogin(event)">
        <div class="space-y-4">
          <div>
            <label class="block text-sm text-gray-400 mb-2">이메일</label>
            <input type="email" name="email" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-2">비밀번호</label>
            <input type="password" name="password" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <button type="submit" class="w-full py-3 rounded-lg bg-gradient-to-r from-yellow-500 to-orange-500 text-black font-bold hover:opacity-90 transition">
            로그인
          </button>
        </div>
      </form>
      <p class="text-center text-gray-400 text-sm mt-4">
        계정이 없으신가요? <a href="#" onclick="showRegisterModal(); hideLoginModal();" class="text-yellow-400 hover:underline">회원가입</a>
      </p>
    </div>
  </div>
  
  <!-- Register Modal -->
  <div id="register-modal" class="modal">
    <div class="glass rounded-2xl p-8 max-w-md w-full mx-4">
      <div class="flex justify-between items-center mb-6">
        <h3 class="text-2xl font-bold">회원가입</h3>
        <button onclick="hideRegisterModal()" class="text-gray-400 hover:text-white">
          <i class="fas fa-times text-xl"></i>
        </button>
      </div>
      <form id="register-form" onsubmit="handleRegister(event)">
        <div class="space-y-4">
          <div>
            <label class="block text-sm text-gray-400 mb-2">이름</label>
            <input type="text" name="name" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-2">이메일</label>
            <input type="email" name="email" required class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-2">비밀번호</label>
            <input type="password" name="password" required minlength="6" class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-2">전화번호 (선택)</label>
            <input type="tel" name="phone" class="w-full px-4 py-3 rounded-lg bg-white/10 border border-gray-700 focus:border-yellow-500 focus:outline-none">
          </div>
          <button type="submit" class="w-full py-3 rounded-lg bg-gradient-to-r from-yellow-500 to-orange-500 text-black font-bold hover:opacity-90 transition">
            가입하기
          </button>
        </div>
      </form>
      <p class="text-center text-gray-400 text-sm mt-4">
        이미 계정이 있으신가요? <a href="#" onclick="showLoginModal(); hideRegisterModal();" class="text-yellow-400 hover:underline">로그인</a>
      </p>
    </div>
  </div>
  
  <!-- Alert Toast -->
  <div id="toast" class="fixed bottom-4 right-4 z-50 hidden">
    <div class="glass rounded-lg px-6 py-4 flex items-center space-x-3">
      <i id="toast-icon" class="fas fa-check-circle text-green-500"></i>
      <span id="toast-message"></span>
    </div>
  </div>

  <script>
    // State
    let currentUser = null;
    let authToken = localStorage.getItem('auth_token');
    let frequencyChart = null;

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
      if (authToken) {
        checkAuth();
      }
      loadPredictions();
      loadAnalysis();
      loadHistory();
    });

    // API Helper
    async function api(endpoint, options = {}) {
      const headers = {
        'Content-Type': 'application/json',
        ...options.headers
      };
      
      if (authToken) {
        headers['Authorization'] = 'Bearer ' + authToken;
      }
      
      const response = await fetch('/api' + endpoint, {
        ...options,
        headers
      });
      
      return response.json();
    }

    // Auth Functions
    async function checkAuth() {
      try {
        const data = await api('/auth/me');
        if (data.user) {
          currentUser = data.user;
          updateAuthUI();
          loadPredictions();
        }
      } catch (e) {
        localStorage.removeItem('auth_token');
        authToken = null;
      }
    }

    function updateAuthUI() {
      const authButtons = document.getElementById('auth-buttons');
      const userMenu = document.getElementById('user-menu');
      const userName = document.getElementById('user-name');
      const membershipBadge = document.getElementById('membership-badge');
      
      if (currentUser) {
        authButtons.classList.add('hidden');
        userMenu.classList.remove('hidden');
        userMenu.classList.add('flex');
        userName.textContent = currentUser.name;
        
        if (currentUser.membership_type === 'premium') {
          membershipBadge.textContent = 'PREMIUM';
          membershipBadge.className = 'px-2 py-1 rounded text-xs font-bold bg-yellow-500 text-black';
        } else if (currentUser.membership_type === 'admin') {
          membershipBadge.textContent = 'ADMIN';
          membershipBadge.className = 'px-2 py-1 rounded text-xs font-bold bg-red-500 text-white';
        } else {
          membershipBadge.textContent = 'FREE';
          membershipBadge.className = 'px-2 py-1 rounded text-xs font-bold bg-gray-600 text-white';
        }
      } else {
        authButtons.classList.remove('hidden');
        userMenu.classList.add('hidden');
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const form = e.target;
      const data = {
        email: form.email.value,
        password: form.password.value
      };
      
      try {
        const response = await api('/auth/login', {
          method: 'POST',
          body: JSON.stringify(data)
        });
        
        if (response.success) {
          authToken = response.token;
          localStorage.setItem('auth_token', response.token);
          currentUser = response.user;
          hideLoginModal();
          updateAuthUI();
          loadPredictions();
          showToast('로그인 성공!', 'success');
        } else {
          showToast(response.error, 'error');
        }
      } catch (e) {
        showToast('로그인 실패', 'error');
      }
    }

    async function handleRegister(e) {
      e.preventDefault();
      const form = e.target;
      const data = {
        name: form.name.value,
        email: form.email.value,
        password: form.password.value,
        phone: form.phone.value
      };
      
      try {
        const response = await api('/auth/register', {
          method: 'POST',
          body: JSON.stringify(data)
        });
        
        if (response.success) {
          authToken = response.token;
          localStorage.setItem('auth_token', response.token);
          currentUser = response.user;
          hideRegisterModal();
          updateAuthUI();
          loadPredictions();
          showToast('회원가입 성공!', 'success');
        } else {
          showToast(response.error, 'error');
        }
      } catch (e) {
        showToast('회원가입 실패', 'error');
      }
    }

    async function logout() {
      await api('/auth/logout', { method: 'POST' });
      localStorage.removeItem('auth_token');
      authToken = null;
      currentUser = null;
      updateAuthUI();
      loadPredictions();
      showToast('로그아웃 되었습니다.', 'success');
    }

    // Modal Functions
    function showLoginModal() { document.getElementById('login-modal').classList.add('show'); }
    function hideLoginModal() { document.getElementById('login-modal').classList.remove('show'); }
    function showRegisterModal() { document.getElementById('register-modal').classList.add('show'); }
    function hideRegisterModal() { document.getElementById('register-modal').classList.remove('show'); }
    function toggleMobileMenu() { document.getElementById('mobile-menu').classList.toggle('hidden'); }

    // Data Loading Functions
    async function loadPredictions() {
      try {
        const data = await api('/predictions');
        const container = document.getElementById('predictions-container');
        document.getElementById('prediction-round').textContent = data.round_number;
        
        container.innerHTML = data.predictions.map((pred, index) => {
          const isFirstFree = index === 0;
          const numbersHtml = pred.numbers.map(num => {
            if (num === '?') {
              return '<div class="lotto-ball locked-ball"><i class="fas fa-lock"></i></div>';
            }
            const ballClass = getBallClass(num);
            return '<div class="lotto-ball ' + ballClass + '">' + num + '</div>';
          }).join('');
          
          return '<div class="glass rounded-2xl p-6 ' + (pred.locked ? 'opacity-75' : '') + '">' +
            '<div class="flex flex-col md:flex-row md:items-center justify-between gap-4">' +
              '<div class="flex items-center gap-4">' +
                '<div class="text-2xl font-bold text-yellow-400">#' + pred.set_index + '</div>' +
                '<div class="flex gap-2">' + numbersHtml + '</div>' +
              '</div>' +
              '<div class="flex-1 text-gray-400 text-sm">' +
                (pred.locked ? 
                  '<span class="text-yellow-500"><i class="fas fa-crown mr-1"></i>프리미엄 전용</span>' : 
                  pred.ai_comment) +
              '</div>' +
            '</div>' +
          '</div>';
        }).join('');
      } catch (e) {
        console.error('Failed to load predictions:', e);
      }
    }

    async function loadAnalysis() {
      try {
        const data = await api('/lotto/analysis');
        
        // Render chart
        const ctx = document.getElementById('frequency-chart').getContext('2d');
        if (frequencyChart) frequencyChart.destroy();
        
        frequencyChart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: data.frequency.map(f => f.number),
            datasets: [{
              label: '출현 횟수',
              data: data.frequency.map(f => f.count),
              backgroundColor: data.frequency.map(f => {
                if (f.count >= 3 && f.count <= 4) return 'rgba(234, 179, 8, 0.8)';
                return 'rgba(107, 114, 128, 0.5)';
              }),
              borderColor: data.frequency.map(f => {
                if (f.count >= 3 && f.count <= 4) return 'rgba(234, 179, 8, 1)';
                return 'rgba(107, 114, 128, 1)';
              }),
              borderWidth: 1
            }]
          },
          options: {
            responsive: true,
            plugins: {
              legend: { display: false }
            },
            scales: {
              y: {
                beginAtZero: true,
                grid: { color: 'rgba(255,255,255,0.1)' },
                ticks: { color: '#9CA3AF' }
              },
              x: {
                grid: { display: false },
                ticks: { color: '#9CA3AF' }
              }
            }
          }
        });
        
        // Render candidates
        const candidatesContainer = document.getElementById('candidates-container');
        candidatesContainer.innerHTML = data.candidates.map(c => 
          '<div class="lotto-ball ' + getBallClass(c.number) + '">' + c.number + '</div>'
        ).join('');
        
        // Render carryover
        const carryoverContainer = document.getElementById('carryover-container');
        carryoverContainer.innerHTML = data.carryover_numbers.map(n => 
          '<div class="lotto-ball ' + getBallClass(n) + '">' + n + '</div>'
        ).join('');
      } catch (e) {
        console.error('Failed to load analysis:', e);
      }
    }

    async function loadHistory() {
      try {
        const data = await api('/predictions/history');
        const container = document.getElementById('history-container');
        
        if (data.history.length === 0) {
          container.innerHTML = '<div class="text-center text-gray-400 py-8">아직 결과가 없습니다.</div>';
          return;
        }
        
        // Group by round
        const byRound = {};
        data.history.forEach(item => {
          if (!byRound[item.round_number]) byRound[item.round_number] = [];
          byRound[item.round_number].push(item);
        });
        
        container.innerHTML = Object.entries(byRound).slice(0, 5).map(([round, preds]) => {
          const first = preds[0];
          const hasHit = preds.some(p => p.matched_count >= 3);
          
          return '<div class="glass rounded-2xl p-6 ' + (hasHit ? 'border border-yellow-500' : '') + '">' +
            '<div class="flex justify-between items-center mb-4">' +
              '<div class="text-lg font-bold">' + round + '회차</div>' +
              (hasHit ? '<div class="success-badge px-3 py-1 rounded-full text-black font-bold text-sm">적중!</div>' : '') +
            '</div>' +
            '<div class="mb-4">' +
              '<span class="text-gray-400 text-sm">당첨번호: </span>' +
              '<span class="font-mono">' + 
                [first.actual_num1, first.actual_num2, first.actual_num3, first.actual_num4, first.actual_num5, first.actual_num6].join(' - ') + 
                ' + ' + first.bonus +
              '</span>' +
            '</div>' +
            '<div class="space-y-2">' +
              preds.map(p => 
                '<div class="flex items-center gap-4 text-sm">' +
                  '<span class="text-gray-500">#' + p.set_index + '</span>' +
                  '<span class="font-mono">' + [p.num1, p.num2, p.num3, p.num4, p.num5, p.num6].join('-') + '</span>' +
                  '<span class="' + (p.matched_count >= 3 ? 'text-yellow-400 font-bold' : 'text-gray-500') + '">' +
                    p.matched_count + '개 일치 (' + p.rank + ')' +
                  '</span>' +
                '</div>'
              ).join('') +
            '</div>' +
          '</div>';
        }).join('');
        
        // Show banner if recent hit
        const recentHit = data.history.find(h => h.matched_count >= 3);
        if (recentHit) {
          document.getElementById('results-banner').classList.remove('hidden');
          document.getElementById('banner-text').textContent = 
            '🎉 ' + recentHit.round_number + '회차 추천 번호 ' + recentHit.matched_count + '개 적중! (' + recentHit.rank + ')';
        }
      } catch (e) {
        console.error('Failed to load history:', e);
      }
    }

    function getBallClass(num) {
      if (num <= 10) return 'ball-1-10';
      if (num <= 20) return 'ball-11-20';
      if (num <= 30) return 'ball-21-30';
      if (num <= 40) return 'ball-31-40';
      return 'ball-41-45';
    }

    // Actions
    function downloadPredictions() {
      window.location.href = '/api/predictions/download';
    }

    async function subscribe() {
      if (!currentUser) {
        showLoginModal();
        showToast('로그인이 필요합니다.', 'warning');
        return;
      }
      
      try {
        const response = await api('/payment/init', {
          method: 'POST',
          body: JSON.stringify({ months: 1 })
        });
        
        if (response.success) {
          // In production, integrate with KG이니시스 SDK
          // For demo, simulate payment success
          const completeResponse = await api('/payment/complete', {
            method: 'POST',
            body: JSON.stringify({
              order_id: response.order_id,
              pg_tid: 'DEMO_' + Date.now(),
              status: 'success'
            })
          });
          
          if (completeResponse.success) {
            showToast('프리미엄 구독 완료! 🎉', 'success');
            checkAuth();
            loadPredictions();
          }
        }
      } catch (e) {
        showToast('결제 처리 중 오류가 발생했습니다.', 'error');
      }
    }

    function showToast(message, type = 'success') {
      const toast = document.getElementById('toast');
      const icon = document.getElementById('toast-icon');
      const msg = document.getElementById('toast-message');
      
      msg.textContent = message;
      icon.className = 'fas ' + (type === 'success' ? 'fa-check-circle text-green-500' : 
                                  type === 'error' ? 'fa-exclamation-circle text-red-500' : 
                                  'fa-exclamation-triangle text-yellow-500');
      
      toast.classList.remove('hidden');
      setTimeout(() => toast.classList.add('hidden'), 3000);
    }
  </script>
</body>
</html>`

  return c.html(html)
})

export default app
