import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';

export default function TestIndexPage() {
  const [testClient, setTestClient] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [caStatus, setCaStatus] = useState<any>(null);

  async function createTestClient() {
    setLoading(true);
    try {
      const res = await fetch('/api/test/create-client', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setTestClient(data.client);
      } else {
        alert(data.error);
      }
    } catch {
      alert('Failed to create test client');
    } finally {
      setLoading(false);
    }
  }

  async function initCA() {
    setLoading(true);
    try {
      const res = await fetch('/api/admin/ca/init', {
        method: 'POST',
        headers: { 'x-admin-secret': process.env.NEXT_PUBLIC_ADMIN_SECRET || 'test-secret' },
      });
      const data = await res.json();
      setCaStatus(data);
    } catch {
      alert('Failed to init CA');
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Head>
        <title>테스트 도구 - 2Check PKI</title>
      </Head>
      <div className="min-h-screen bg-gray-100 py-8 px-4">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-2xl font-bold mb-6">2Check PKI 테스트 도구</h1>

          {/* CA 초기화 */}
          <div className="bg-white rounded-lg shadow p-6 mb-4">
            <h2 className="font-semibold mb-4">1. CA 초기화</h2>
            <p className="text-sm text-gray-600 mb-4">
              루트 CA와 중간 CA를 생성합니다. (최초 1회만 실행)
            </p>
            <button
              onClick={initCA}
              disabled={loading}
              className="bg-purple-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              CA 초기화
            </button>
            {caStatus && (
              <pre className="mt-4 bg-gray-100 p-3 rounded text-xs overflow-x-auto">
                {JSON.stringify(caStatus, null, 2)}
              </pre>
            )}
          </div>

          {/* 테스트 클라이언트 생성 */}
          <div className="bg-white rounded-lg shadow p-6 mb-4">
            <h2 className="font-semibold mb-4">2. 테스트 OAuth 클라이언트 생성</h2>
            <button
              onClick={createTestClient}
              disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              클라이언트 생성
            </button>
            {testClient && (
              <div className="mt-4 p-4 bg-green-50 rounded">
                <p className="font-medium text-green-800 mb-2">클라이언트 생성 완료!</p>
                <div className="text-sm space-y-1">
                  <p><strong>Client ID:</strong> <code className="bg-white px-1">{testClient.clientId}</code></p>
                  <p><strong>Client Secret:</strong> <code className="bg-white px-1">{testClient.clientSecret}</code></p>
                </div>
              </div>
            )}
          </div>

          {/* 테스트 링크 */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="font-semibold mb-4">3. 테스트 페이지</h2>
            <ul className="space-y-2">
              <li>
                <Link href="/test/oauth-client" className="text-blue-600 hover:underline">
                  → OAuth2 클라이언트 테스트
                </Link>
              </li>
              <li>
                <Link href="/certificates/issue" className="text-blue-600 hover:underline">
                  → 인증서 발급 테스트
                </Link>
              </li>
              <li>
                <Link href="/auth/certificate" className="text-blue-600 hover:underline">
                  → 인증서 로그인 테스트
                </Link>
              </li>
              <li>
                <Link href="/docs" className="text-blue-600 hover:underline">
                  → API 문서
                </Link>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}
