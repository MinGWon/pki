import Head from 'next/head';
import Link from 'next/link';

export default function DocsPage() {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://pki.2check.io';

  return (
    <>
      <Head>
        <title>개발자 문서 - 2Check PKI</title>
      </Head>
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-4xl mx-auto py-12 px-4">
          <h1 className="text-3xl font-bold mb-8">2Check PKI 개발자 문서</h1>

          {/* OAuth2 연동 가이드 */}
          <section className="bg-white rounded-xl shadow p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">OAuth2 연동 가이드</h2>
            
            <h3 className="font-medium mt-4 mb-2">1. 클라이언트 등록</h3>
            <p className="text-gray-600 text-sm mb-2">
              관리자에게 클라이언트 등록을 요청하여 client_id와 client_secret을 발급받습니다.
            </p>

            <h3 className="font-medium mt-4 mb-2">2. Authorization 요청</h3>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded text-sm overflow-x-auto">
{`GET ${baseUrl}/api/oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://your-app.com/callback
  &scope=openid profile email
  &state=RANDOM_STATE
  &code_challenge=CODE_CHALLENGE
  &code_challenge_method=S256`}
            </pre>

            <h3 className="font-medium mt-4 mb-2">3. Token 교환</h3>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded text-sm overflow-x-auto">
{`POST ${baseUrl}/api/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://your-app.com/callback
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&code_verifier=CODE_VERIFIER`}
            </pre>

            <h3 className="font-medium mt-4 mb-2">4. 사용자 정보 조회</h3>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded text-sm overflow-x-auto">
{`GET ${baseUrl}/api/oauth/userinfo
Authorization: Bearer ACCESS_TOKEN`}
            </pre>
          </section>

          {/* API 엔드포인트 */}
          <section className="bg-white rounded-xl shadow p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">API 엔드포인트</h2>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2">엔드포인트</th>
                  <th className="text-left py-2">설명</th>
                </tr>
              </thead>
              <tbody className="text-gray-600">
                <tr className="border-b">
                  <td className="py-2"><code>/api/oauth/authorize</code></td>
                  <td>Authorization 요청</td>
                </tr>
                <tr className="border-b">
                  <td className="py-2"><code>/api/oauth/token</code></td>
                  <td>Access Token 발급</td>
                </tr>
                <tr className="border-b">
                  <td className="py-2"><code>/api/oauth/userinfo</code></td>
                  <td>사용자 정보 조회</td>
                </tr>
                <tr className="border-b">
                  <td className="py-2"><code>/api/oauth/revoke</code></td>
                  <td>토큰 폐기</td>
                </tr>
                <tr className="border-b">
                  <td className="py-2"><code>/api/oauth/introspect</code></td>
                  <td>토큰 검증</td>
                </tr>
                <tr>
                  <td className="py-2"><code>/.well-known/oauth-authorization-server</code></td>
                  <td>OAuth2 메타데이터</td>
                </tr>
              </tbody>
            </table>
          </section>

          {/* iframe 연동 */}
          <section className="bg-white rounded-xl shadow p-6">
            <h2 className="text-xl font-semibold mb-4">iframe 연동 (선택)</h2>
            <p className="text-gray-600 text-sm mb-4">
              팝업 대신 iframe으로 인증 UI를 임베드할 수 있습니다.
            </p>
            <pre className="bg-gray-900 text-gray-100 p-4 rounded text-sm overflow-x-auto">
{`<iframe 
  id="pki-auth" 
  src="${baseUrl}/auth/iframe"
  style="width: 400px; height: 300px; border: none;"
></iframe>

<script>
window.addEventListener('message', (e) => {
  if (e.origin !== '${baseUrl}') return;
  
  if (e.data.type === 'PKI_AUTH_RESPONSE') {
    const { code, state } = e.data.payload;
    // code로 토큰 교환 진행
  }
});

// 인증 요청 전송
document.getElementById('pki-auth').contentWindow.postMessage({
  type: 'PKI_AUTH_REQUEST',
  payload: {
    clientId: 'YOUR_CLIENT_ID',
    redirectUri: 'https://your-app.com/callback',
    scope: 'openid profile',
    state: 'RANDOM_STATE'
  }
}, '${baseUrl}');
</script>`}
            </pre>
          </section>

          <div className="mt-6 text-center">
            <Link href="/" className="text-blue-600 hover:underline">
              ← 홈으로 돌아가기
            </Link>
          </div>
        </div>
      </div>
    </>
  );
}
