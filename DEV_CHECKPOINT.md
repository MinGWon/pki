# PKI 기반 인증 시스템 (pki.2check.io) 개발 체크리스트

## 📋 프로젝트 개요
- **목표**: 한국 공인인증서 스타일의 PKI 기반 인증 시스템
- **연동 방식**: OAuth2 + iframe 인증서 선택창
- **서비스 URL**: https://pki.2check.io

### 기술 스택
- **ORM**: Prisma
- **Database**: MySQL
- **Backend**: Next.js 14 (App Router)
- **Frontend**: Next.js + React + Tailwind CSS
- **Local Agent**: C# (.NET 8.0) + 로컬 HTTP 서버

---

## 🔧 공통 컴포넌트

### CertificateSelectModal (인증서 선택 모달)

인증서 선택이 필요한 모든 곳에서 공통으로 사용하는 모달 컴포넌트입니다.

**파일 위치**: `src/components/CertificateSelectModal.tsx`

#### 사용법

```tsx
import CertificateSelectModal from '@/components/CertificateSelectModal';

// 기본 사용 (로그인)
<CertificateSelectModal
  isOpen={isOpen}
  onClose={() => setIsOpen(false)}
  onSelect={(result) => {
    console.log(result.user);      // 인증된 사용자 정보
    console.log(result.signature); // 서명 값
    console.log(result.serialNumber); // 인증서 일련번호
  }}
  title="인증서 로그인"
  description="로그인에 사용할 인증서를 선택하세요."
/>

// 서명만 필요한 경우 (검증 생략)
<CertificateSelectModal
  isOpen={isOpen}
  onClose={() => setIsOpen(false)}
  onSelect={(result) => {
    console.log(result.signature); // 서명 값만 사용
  }}
  title="전자서명"
  description="서명에 사용할 인증서를 선택하세요."
  skipVerify={true}  // 서버 검증 생략
/

// 커스텀 엔드포인트 사용
<CertificateSelectModal
  isOpen={isOpen}
  onClose={() => setIsOpen(false)}
  onSelect={handleSelect}
  challengeEndpoint="/api/custom/challenge"
  verifyEndpoint="/api/custom/verify"
/>
```

#### Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `isOpen` | `boolean` | required | 모달 표시 여부 |
| `onClose` | `() => void` | required | 모달 닫기 콜백 |
| `onSelect` | `(result) => void` | required | 인증 완료 콜백 |
| `title` | `string` | `"인증서 선택"` | 모달 제목 |
| `description` | `string` | `"사용할 인증서를 선택하세요."` | 설명 텍스트 |
| `challengeEndpoint` | `string` | `"/api/auth/challenge"` | 챌린지 요청 API |
| `verifyEndpoint` | `string` | `"/api/auth/signature/verify"` | 서명 검증 API |
| `skipVerify` | `boolean` | `false` | 서명 검증 생략 여부 |

#### onSelect 콜백 결과

```typescript
interface SelectResult {
  certId: string;        // Agent 내 인증서 ID
  serialNumber: string;  // 인증서 일련번호
  signature: string;     // Base64 인코딩된 서명
  userId?: string;       // 사용자 ID (skipVerify=false일 때)
  user?: {               // 사용자 정보 (skipVerify=false일 때)
    id: string;
    name: string;
    email: string;
  };
}
```

#### 사용 예시

1. **메인 페이지 로그인** (`src/pages/index.tsx`)
2. **관리자 로그인** (`src/pages/admin/index.tsx`)
3. **OAuth2 인증** (`src/pages/auth/certificate.tsx`)

---

### LoginModal (로그인 모달)

`CertificateSelectModal`을 래핑한 간편 로그인 모달입니다.

**파일 위치**: `src/components/LoginModal.tsx`

```tsx
import LoginModal from '@/components/LoginModal';

<LoginModal
  isOpen={isLoginModalOpen}
  onClose={() => setIsLoginModalOpen(false)}
  onSuccess={(user) => {
    console.log('로그인 성공:', user.name);
  }}
/>
```

---

### IssueCertificateModal (인증서 발급 모달)

인증서 발급 프로세스를 처리하는 모달입니다.

**파일 위치**: `src/components/IssueCertificateModal.tsx`

```tsx
import IssueCertificateModal from '@/components/IssueCertificateModal';

<IssueCertificateModal
  isOpen={isIssueModalOpen}
  onClose={() => setIsIssueModalOpen(false)}
/>
```

---

### CertificateSelectEmbed (임베드용 인증서 선택)

iframe이나 전체 페이지에서 사용하는 인증서 선택 컴포넌트입니다. 모달이 아닌 페이지 형태입니다.

**파일 위치**: `src/components/CertificateSelectEmbed.tsx`

```tsx
import CertificateSelectEmbed from '@/components/CertificateSelectEmbed';

// iframe 또는 페이지에서 사용
<CertificateSelectEmbed
  onSelect={(result) => {
    console.log(result.user);
    // 리다이렉트 처리
  }}
  onCancel={() => {
    // 취소 처리
  }}
  title="인증서 로그인"
  description="로그인에 사용할 인증서를 선택하세요."
/>
```

#### CertificateSelectModal vs CertificateSelectEmbed

| 컴포넌트 | 용도 | 스타일 |
|---------|------|--------|
| `CertificateSelectModal` | 팝업 모달 | 오버레이 + 중앙 모달 |
| `CertificateSelectEmbed` | iframe/페이지 | 전체 영역 채움 |

#### iframe 사용 예시 (클라이언트 측)

```html
<iframe 
  src="https://pki.2check.io/auth/iframe?client_id=xxx&redirect_uri=xxx&state=xxx"
  width="500"
  height="600"
  style="border: none;"
></iframe>

<script>
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://pki.2check.io') return;
  
  if (event.data.type === 'success') {
    console.log('인증 성공, code:', event.data.code);
    // code로 토큰 교환
  } else if (event.data.type === 'cancel') {
    console.log('사용자가 취소함');
  } else if (event.data.type === 'error') {
    console.error('오류:', event.data.message);
  }
});
</script>
```

---

## 0. 🖥️ 로컬 Agent (C#)

### 0.1 Agent 개요
- **역할**: 사용자 PC에 인증서 저장/로드/서명 처리
- **저장 경로**: `{Drive}:\2check\cert\`
- **통신 방식**: 로컬 HTTP 서버 (localhost:52080)

### 0.2 Agent HTTP API
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/health` | GET | Agent 상태 확인 |
| `/api/drives` | GET | 드라이브 목록 조회 |
| `/api/certificates` | GET | 저장된 인증서 목록 조회 |
| `/api/certificates` | POST | 새 인증서 저장 (PKCS#12) |
| `/api/certificates/{id}` | DELETE | 인증서 삭제 |
| `/api/certificates/{id}/sign` | POST | 개인키로 데이터 서명 |

### 0.3 중요 사항

#### 한글 이름 처리
- 인증서 내부 Subject는 Base64로 인코딩됨 (`B64_7ZmN6ri467F0`)
- metadata.json에는 웹에서 전달받은 원본 한글 저장
- Agent는 P12에서 Subject 추출하지 말고, 웹에서 전달받은 metadata 그대로 저장

#### JSON 저장 시 UTF-8 인코딩
```csharp
var options = new JsonSerializerOptions
{
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    WriteIndented = true
};
File.WriteAllText(path, JsonSerializer.Serialize(metadata, options), Encoding.UTF8);
```

#### 보안
- metadata.json 위조해도 보안 위험 없음 (서버가 실제 서명 검증)
- serialNumber는 해시로 저장 (선택사항)
- 비밀번호는 서명 시에만 전달, 저장 시 전달 안함

---

## 1. 🔐 인증서 관리 (Certificate Management)

### 1.1 인증서 발급
- [x] CA(Certificate Authority) 서버 구축
- [x] 루트 인증서 생성
- [x] 중간 인증서 생성
- [x] 사용자 인증서 발급 API
- [x] 인증서 발급 모달 (IssueCertificateModal)
- [x] 한글 이름 ASCII 변환 (Base64 인코딩)

### 1.2 인증서 저장
- [x] Agent를 통한 PC 저장
- [x] 파일 다운로드 (PKCS#12 / .p12)
- [x] 드라이브 선택 기능

### 1.3 인증서 관리
- [x] 인증서 목록 조회
- [x] 인증서 상세 조회
- [x] 인증서 폐지 (Revocation)
- [x] CRL 관리
- [x] OCSP 서버

---

## 2. 🖥️ 프론트엔드 (Client-Side)

### 2.1 인증서 선택 UI
- [x] 공통 인증서 선택 모달 (CertificateSelectModal)
- [x] 인증서 목록 테이블 표시
- [x] 인증서 상세 정보 (발급자, 유효기간, 상태)
- [x] 비밀번호 입력
- [x] Agent 미설치 안내

### 2.2 페이지
- [x] 메인 페이지 (인증서 발급, 로그인)
- [x] 관리자 페이지 (/admin)
- [x] OAuth2 인증 페이지 (/auth/certificate)
- [x] 개발자 문서 (/docs)

---

## 3. 🔗 OAuth2 서버

### 3.1 OAuth2 엔드포인트
- [x] `/oauth/authorize` - 인증 요청
- [x] `/oauth/token` - 토큰 발급
- [x] `/oauth/revoke` - 토큰 폐기
- [x] `/oauth/introspect` - 토큰 검증
- [x] `/oauth/userinfo` - 사용자 정보

### 3.2 클라이언트 관리
- [x] 클라이언트 등록 API
- [x] 관리자 페이지에서 클라이언트 관리

---

## 4. 🛡️ 백엔드 API

### 4.1 인증 API
- [x] `POST /api/auth/signature/verify` - 서명 검증
- [x] `GET /api/auth/challenge` - 챌린지 생성
- [x] `POST /api/auth/code` - Authorization Code 생성

### 4.2 관리자 API
- [x] `POST /api/admin/register` - 관리자 등록
- [x] `POST /api/admin/verify` - 관리자 확인
- [x] `GET /api/admin/dashboard` - 대시보드 데이터
- [x] `GET/POST/DELETE /api/admin/clients` - 클라이언트 관리
- [x] `GET/PATCH /api/admin/certificates` - 인증서 관리
- [x] `GET /api/admin/logs` - 감사 로그

---

## 5. 🗄️ 데이터베이스 스키마

### 5.1 주요 모델
- [x] `User` - 사용자 정보 (isAdmin 필드 추가)
- [x] `Certificate` - 발급된 인증서
- [x] `OAuthClient` - OAuth2 클라이언트
- [x] `OAuthToken` - 발급된 토큰
- [x] `OAuthAuthorizationCode` - 인증 코드
- [x] `RevokedCertificate` - 폐지된 인증서
- [x] `Challenge` - 챌린지
- [x] `AuditLog` - 감사 로그

---

## 6. 📅 마일스톤

| 단계 | 내용 | 상태 |
|------|------|------|
| Phase 1 | 기본 CA 및 인증서 발급 | ✅ 완료 |
| Phase 2 | 인증서 선택 UI (공통 모달) | ✅ 완료 |
| Phase 3 | OAuth2 서버 구현 | ✅ 완료 |
| Phase 4 | 관리자 페이지 | ✅ 완료 |
| Phase 5 | Agent 연동 | ✅ 완료 |
| Phase 6 | 보안 강화 및 최적화 | ⬜ 예정 |
| Phase 7 | 배포 | ⬜ 예정 |

---

## 7. 🔧 트러블슈팅

### PKCS#12 생성 오류
- **원인**: 한글 이름이 인증서 Subject에 포함되어 Base64 인코딩 깨짐
- **해결**: 한글을 `B64_xxxx` 형태로 ASCII 변환 후 인증서 생성

### metadata.json 한글 깨짐
- **원인**: Agent에서 P12 파일의 Subject 직접 추출
- **해결**: 웹에서 전달받은 metadata 그대로 저장, UTF-8 인코딩 명시

### Agent CORS 오류
- **원인**: Agent에서 허용된 Origin 미설정
- **해결**: `http://localhost:3000`, `https://pki.2check.io` 허용
