import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function generateState(): string {
  return crypto.randomUUID();
}

export default function OAuthTestClient() {
  const router = useRouter();
  const [config, setConfig] = useState({
    clientId: '',
    clientSecret: '',
    redirectUri: typeof window !== 'undefined' ? `${window.location.origin}/test/oauth-client` : '',
    scope: 'openid profile email',
  });
  const [authCode, setAuthCode] = useState<string | null>(null);
  const [tokens, setTokens] = useState<any>(null);
  const [userInfo, setUserInfo] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const pkiUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  // URL에서 code 파라미터 확인
  useEffect(() => {
    const code = router.query.code as string;
    const state = router.query.state as string;
    const storedState = sessionStorage.getItem('oauth_state');

    if (code) {
      if (state && state !== storedState) {
        setError('State mismatch - possible CSRF attack');
        return;
      }
      setAuthCode(code);
      sessionStorage.removeItem('oauth_state');
    }

    // 저장된 설정 복원
    const savedConfig = sessionStorage.getItem('oauth_config');
    if (savedConfig) {
      setConfig(JSON.parse(savedConfig));
    }
  }, [router.query]);

  async function startAuth() {
    if (!config.clientId) {
      setError('Client ID를 입력해주세요.');
      return;
    }

    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // 세션에 저장
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_code_verifier', codeVerifier);
    sessionStorage.setItem('oauth_config', JSON.stringify(config));

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${pkiUrl}/api/oauth/authorize?${params}`;
  }

  async function exchangeToken() {
    if (!authCode) return;

    setLoading(true);
    setError(null);

    try {
      const codeVerifier = sessionStorage.getItem('oauth_code_verifier');

      const res = await fetch(`${pkiUrl}/api/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: authCode,
          redirect_uri: config.redirectUri,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          code_verifier: codeVerifier || '',
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error_description || data.error || 'Token exchange failed');
      }

      setTokens(data);
      sessionStorage.removeItem('oauth_code_verifier');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Token exchange failed');
    } finally {
      setLoading(false);
    }
  }

  async function fetchUserInfo() {
    if (!tokens?.access_token) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`${pkiUrl}/api/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch user info');
      }

      setUserInfo(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch user info');
    } finally {
      setLoading(false);
    }
  }

  async function introspectToken() {
    if (!tokens?.access_token) return;

    setLoading(true);
    try {
      const res = await fetch(`${pkiUrl}/api/oauth/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }),
      });
      const data = await res.json();
      alert(JSON.stringify(data, null, 2));
    } catch (err) {
      setError('Introspect failed');
    } finally {
      setLoading(false);
    }
  }

  async function revokeToken() {
    if (!tokens?.access_token) return;

    setLoading(true);
    try {
      await fetch(`${pkiUrl}/api/oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }),
      });
      setTokens(null);
      setUserInfo(null);
      alert('Token revoked');
    } catch (err) {
      setError('Revoke failed');
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setAuthCode(null);
    setTokens(null);
    setUserInfo(null);
    setError(null);
    sessionStorage.clear();
    router.replace('/test/oauth-client', undefined, { shallow: true });
  }

  return (
    <>
      <Head>
        <title>OAuth2 테스트 클라이언트</title>
      </Head>
      <div className="min-h-screen bg-gray-100 py-8 px-4">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-2xl font-bold mb-6">OAuth2 테스트 클라이언트</h1>

          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-600">
              {error}
            </div>
          )}

          {/* Step 1: 설정 */}
          <div className="bg-white rounded-lg shadow p-6 mb-4">
            <h2 className="font-semibold mb-4">1. 클라이언트 설정</h2>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1">Client ID</label>
                <input
                  type="text"
                  value={config.clientId}
                  onChange={(e) => setConfig({ ...config, clientId: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm"
                  placeholder="발급받은 client_id"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Client Secret</label>
                <input
                  type="password"
                  value={config.clientSecret}
                  onChange={(e) => setConfig({ ...config, clientSecret: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm"
                  placeholder="발급받은 client_secret"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Redirect URI</label>
                <input
                  type="text"
                  value={config.redirectUri}
                  onChange={(e) => setConfig({ ...config, redirectUri: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Scope</label>
                <input
                  type="text"
                  value={config.scope}
                  onChange={(e) => setConfig({ ...config, scope: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm"
                />
              </div>
            </div>
            <button
              onClick={startAuth}
              disabled={loading}
              className="mt-4 bg-blue-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              인증 시작
            </button>
          </div>

          {/* Step 2: Authorization Code */}
          {authCode && (
            <div className="bg-white rounded-lg shadow p-6 mb-4">
              <h2 className="font-semibold mb-4">2. Authorization Code 수신</h2>
              <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto mb-4">
                {authCode}
              </pre>
              <button
                onClick={exchangeToken}
                disabled={loading || !!tokens}
                className="bg-green-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
              >
                {loading ? '처리중...' : 'Token 교환'}
              </button>
            </div>
          )}

          {/* Step 3: Tokens */}
          {tokens && (
            <div className="bg-white rounded-lg shadow p-6 mb-4">
              <h2 className="font-semibold mb-4">3. Access Token 수신</h2>
              <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto mb-4">
                {JSON.stringify(tokens, null, 2)}
              </pre>
              <div className="flex gap-2">
                <button
                  onClick={fetchUserInfo}
                  disabled={loading}
                  className="bg-blue-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
                >
                  사용자 정보 조회
                </button>
                <button
                  onClick={introspectToken}
                  disabled={loading}
                  className="bg-gray-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
                >
                  Token 검증
                </button>
                <button
                  onClick={revokeToken}
                  disabled={loading}
                  className="bg-red-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
                >
                  Token 폐기
                </button>
              </div>
            </div>
          )}

          {/* Step 4: User Info */}
          {userInfo && (
            <div className="bg-white rounded-lg shadow p-6 mb-4">
              <h2 className="font-semibold mb-4">4. 사용자 정보</h2>
              <pre className="bg-gray-100 p-3 rounded text-xs overflow-x-auto">
                {JSON.stringify(userInfo, null, 2)}
              </pre>
            </div>
          )}

          <button
            onClick={reset}
            className="text-gray-600 underline text-sm"
          >
            처음부터 다시
          </button>
        </div>
      </div>
    </>
  );
}
