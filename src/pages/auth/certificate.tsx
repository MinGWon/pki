import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import CertificateImport from '@/components/CertificateImport';
import { ParsedPKCS12 } from '@/lib/pkcs12-parser';
import { useCertificate } from '@/hooks/useCertificate';
import CertificateSelectEmbed from '@/components/CertificateSelectEmbed';

interface Certificate {
  certId: string;
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore: string;
  notAfter: string;
  isExpired: boolean;
}

type AuthStep = 'loading' | 'no-agent' | 'select' | 'import' | 'signing' | 'success' | 'error';

export default function CertificateSelectPage() {
  const router = useRouter();
  const [step, setStep] = useState<AuthStep>('loading');
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCert, setSelectedCert] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [showImport, setShowImport] = useState(false);
  
  const { 
    certificates: localCerts, 
    loadCertificates: loadLocalCerts,
    saveCertificate,
  } = useCertificate();

  const agentUrl = process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:52080';

  const checkAgent = useCallback(async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const res = await fetch(`${agentUrl}/api/health`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!res.ok) throw new Error('Agent not healthy');

      const certRes = await fetch(`${agentUrl}/api/certificates`);
      if (!certRes.ok) throw new Error('Failed to load certificates');

      const data = await certRes.json();
      setCertificates(data);
      setStep('select');
    } catch {
      if (retryCount < 3) {
        setTimeout(() => setRetryCount((c) => c + 1), 2000);
      } else {
        setStep('no-agent');
      }
    }
  }, [agentUrl, retryCount]);

  useEffect(() => {
    if (router.isReady) {
      checkAgent();
    }
  }, [router.isReady, checkAgent]);

  useEffect(() => {
    loadLocalCerts();
  }, [loadLocalCerts]);

  async function handleImport(parsed: ParsedPKCS12, file: File) {
    try {
      const buffer = await file.arrayBuffer();
      await saveCertificate(parsed, buffer);
      setShowImport(false);
      await loadLocalCerts();
    } catch (err) {
      alert(err instanceof Error ? err.message : '저장 실패');
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    if (!selectedCert || !password) {
      setError('인증서와 비밀번호를 입력해주세요.');
      return;
    }

    setStep('signing');
    setError(null);

    try {
      // 1. 챌린지 요청
      const challengeRes = await fetch('/api/auth/challenge');
      if (!challengeRes.ok) throw new Error('챌린지 생성 실패');
      const { challenge } = await challengeRes.json();

      // 2. Agent에 서명 요청
      const signRes = await fetch(`${agentUrl}/api/certificates/${selectedCert}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: challenge, password }),
      });

      if (!signRes.ok) {
        const err = await signRes.json();
        throw new Error(err.error || '서명 실패');
      }

      const { signature, serialNumber } = await signRes.json();

      // 3. 서명 검증
      const verifyRes = await fetch('/api/auth/signature/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge, signature, certificateSerialNumber: serialNumber }),
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json();
        throw new Error(err.error || '인증 실패');
      }

      const { user } = await verifyRes.json();

      // 4. Authorization Code 생성
      // client_id가 없으면 기본값 사용 (테스트용)
      const clientId = router.query.client_id as string;
      const redirectUri = router.query.redirect_uri as string;

      console.log('[CERT AUTH] code 요청:', { 
        userId: user.id, 
        clientId, 
        redirectUri,
        hasQuery: !!router.query.client_id,
      });

      // client_id가 없는 경우 (직접 로그인)
      if (!clientId || !redirectUri) {
        // OAuth 플로우가 아닌 직접 로그인
        setStep('success');
        setTimeout(() => {
          router.push('/'); // 홈으로 이동
        }, 1500);
        return;
      }

      const codeRes = await fetch('/api/auth/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: user.id,
          clientId,
          redirectUri,
          scope: router.query.scope || '',
          codeChallenge: router.query.code_challenge || null,
          codeChallengeMethod: router.query.code_challenge_method || null,
        }),
      });

      if (!codeRes.ok) {
        const err = await codeRes.json();
        console.error('[CERT AUTH] code 생성 실패:', err);
        throw new Error(err.detail || err.error || '인증 코드 생성 실패');
      }

      const { code } = await codeRes.json();

      setStep('success');

      // 5. 리다이렉트
      setTimeout(() => {
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (router.query.state) {
          redirectUrl.searchParams.set('state', router.query.state as string);
        }
        window.location.href = redirectUrl.toString();
      }, 1500);
    } catch (err) {
      console.error('[CERT AUTH] 오류:', err);
      setError(err instanceof Error ? err.message : '인증 중 오류 발생');
      setStep('error');
    }
  }

  function formatDN(dn: string): string {
    const cnMatch = dn.match(/CN=([^,]+)/);
    return cnMatch ? cnMatch[1] : dn;
  }

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString('ko-KR');
  }

  function getDaysRemaining(dateStr: string): number {
    const diff = new Date(dateStr).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  // 로딩 화면
  if (step === 'loading') {
    return (
      <div className="page-center">
        <div className="text-center animate-fade-in">
          <div className="spinner h-14 w-14 mx-auto" />
          <p className="mt-6 text-gray-600 font-medium">인증서 Agent 연결 중...</p>
          {retryCount > 0 && (
            <p className="mt-2 text-sm text-gray-400">재시도 중... ({retryCount}/3)</p>
          )}
        </div>
      </div>
    );
  }

  // Agent 미설치 화면
  if (step === 'no-agent') {
    return (
      <>
        <Head>
          <title>Agent 설치 필요 - 2Check PKI</title>
        </Head>
        <div className="page-center">
          <div className="card p-8 max-w-md w-full animate-slide-up">
            <div className="text-center mb-8">
              <div className="w-20 h-20 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-lg">
                <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-gray-900">인증서 Agent 필요</h1>
              <p className="mt-3 text-gray-500">
                인증서 로그인을 위해 2Check Agent 설치가 필요합니다.
              </p>
            </div>

            <div className="space-y-3">
              <a href="/download/agent" className="btn-primary btn-lg w-full">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Agent 다운로드
              </a>
              <button
                onClick={() => {
                  setRetryCount(0);
                  setStep('loading');
                  checkAgent();
                }}
                className="btn-secondary btn-lg w-full"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                다시 연결 시도
              </button>
            </div>

            <div className="mt-8 p-5 bg-gray-50 rounded-xl">
              <h3 className="font-semibold text-gray-900 mb-3 flex items-center">
                <svg className="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                설치 안내
              </h3>
              <ol className="text-sm text-gray-600 space-y-2">
                <li className="flex items-start">
                  <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3">1</span>
                  <span>위 버튼을 클릭하여 Agent를 다운로드합니다.</span>
                </li>
                <li className="flex items-start">
                  <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3">2</span>
                  <span>다운로드한 파일을 실행하여 설치합니다.</span>
                </li>
                <li className="flex items-start">
                  <span className="flex-shrink-0 w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-medium mr-3">3</span>
                  <span>설치 완료 후 &quot;다시 연결 시도&quot;를 클릭합니다.</span>
                </li>
              </ol>
            </div>
          </div>
        </div>
      </>
    );
  }

  // 서명 중 화면
  if (step === 'signing') {
    return (
      <div className="page-center">
        <div className="text-center animate-fade-in">
          <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-lg">
            <div className="spinner h-10 w-10 border-white border-t-transparent" />
          </div>
          <h2 className="text-xl font-bold text-gray-900">인증서로 서명 중</h2>
          <p className="mt-2 text-gray-500">잠시만 기다려주세요...</p>
        </div>
      </div>
    );
  }

  // 성공 화면
  if (step === 'success') {
    return (
      <div className="page-center">
        <div className="text-center animate-slide-up">
          <div className="w-20 h-20 bg-gradient-to-br from-green-400 to-emerald-500 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-lg">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900">인증 성공</h2>
          <p className="mt-2 text-gray-500">잠시 후 이동합니다...</p>
          <div className="mt-6">
            <div className="w-32 h-1 bg-gray-200 rounded-full mx-auto overflow-hidden">
              <div className="h-full bg-green-500 rounded-full animate-[loading_1.5s_ease-in-out]" style={{ animation: 'loading 1.5s ease-in-out forwards' }} />
            </div>
          </div>
        </div>
        <style jsx>{`
          @keyframes loading {
            from { width: 0; }
            to { width: 100%; }
          }
        `}</style>
      </div>
    );
  }

  // import 모달
  if (showImport) {
    return (
      <>
        <Head>
          <title>인증서 가져오기 - 2Check PKI</title>
        </Head>
        <div className="page-center">
          <CertificateImport
            onImport={handleImport}
            onCancel={() => setShowImport(false)}
          />
        </div>
      </>
    );
  }

  const { client_id, redirect_uri, state, scope, code_challenge, code_challenge_method } = router.query;

  async function handleSelect(result: { userId?: string; user?: any; serialNumber: string }) {
    if (!result.userId) {
      console.error('User ID not found');
      return;
    }

    // client_id가 없으면 직접 로그인 (OAuth 아님)
    if (!client_id || !redirect_uri) {
      // 로그인 성공 후 홈으로 이동
      window.location.href = '/';
      return;
    }

    try {
      // Authorization Code 생성
      const codeRes = await fetch('/api/auth/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: result.userId,
          clientId: client_id,
          redirectUri: redirect_uri,
          scope: scope || '',
          codeChallenge: code_challenge || null,
          codeChallengeMethod: code_challenge_method || null,
        }),
      });

      if (!codeRes.ok) {
        const err = await codeRes.json();
        throw new Error(err.error || '인증 코드 생성 실패');
      }

      const { code } = await codeRes.json();

      // 리다이렉트
      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('code', code);
      if (state) {
        redirectUrl.searchParams.set('state', state as string);
      }
      window.location.href = redirectUrl.toString();
    } catch (error) {
      console.error('Auth code generation failed:', error);
    }
  }

  function handleCancel() {
    if (redirect_uri) {
      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('error', 'access_denied');
      redirectUrl.searchParams.set('error_description', 'User cancelled the request');
      if (state) {
        redirectUrl.searchParams.set('state', state as string);
      }
      window.location.href = redirectUrl.toString();
    } else {
      window.close();
    }
  }

  // 인증서 선택 화면
  return (
    <>
      <Head>
        <title>인증서 로그인 - 2Check PKI</title>
      </Head>
      <div className="page-center">
        <div className="card p-8 max-w-md w-full animate-slide-up">
          {/* 헤더 */}
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg">
              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-2xl font-bold text-gray-900">인증서 로그인</h1>
            <p className="mt-2 text-gray-500">인증서를 선택하고 비밀번호를 입력하세요.</p>
          </div>

          {/* 에러 메시지 */}
          {(error || step === 'error') && (
            <div className="alert-error mb-6 flex items-start">
              <svg className="w-5 h-5 mr-2 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <div>
                <p className="font-medium">{error}</p>
                {step === 'error' && (
                  <button
                    onClick={() => setStep('select')}
                    className="mt-1 text-red-800 underline text-sm"
                  >
                    다시 시도
                  </button>
                )}
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* 인증서 목록 */}
            <div className="mb-6">
              <label className="label">인증서 선택</label>
              <div className="space-y-3 max-h-72 overflow-y-auto custom-scrollbar p-1">
                {certificates.length === 0 ? (
                  <div className="text-center py-12 border-2 border-dashed border-gray-200 rounded-xl">
                    <svg className="w-12 h-12 mx-auto text-gray-300 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <p className="text-gray-500 font-medium">저장된 인증서가 없습니다.</p>
                    <p className="text-gray-400 text-sm mt-1">아래에서 인증서를 가져오세요.</p>
                  </div>
                ) : (
                  certificates.map((cert) => {
                    const daysRemaining = getDaysRemaining(cert.notAfter);
                    const isExpiringSoon = daysRemaining > 0 && daysRemaining <= 30;
                    
                    return (
                      <label
                        key={cert.certId}
                        className={`block p-4 rounded-xl border-2 cursor-pointer transition-all duration-200 ${
                          selectedCert === cert.certId
                            ? 'border-blue-500 bg-blue-50 shadow-sm'
                            : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                        } ${cert.isExpired ? 'opacity-60 cursor-not-allowed bg-gray-50' : ''}`}
                      >
                        <input
                          type="radio"
                          name="certificate"
                          value={cert.certId}
                          checked={selectedCert === cert.certId}
                          onChange={() => setSelectedCert(cert.certId)}
                          disabled={cert.isExpired}
                          className="sr-only"
                        />
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center">
                              <span className="font-semibold text-gray-900 truncate">
                                {formatDN(cert.subjectDN)}
                              </span>
                            </div>
                            <p className="text-sm text-gray-500 mt-1 truncate">
                              {formatDN(cert.issuerDN)}
                            </p>
                          </div>
                          {selectedCert === cert.certId && (
                            <div className="flex-shrink-0 ml-3">
                              <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center">
                                <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                </svg>
                              </div>
                            </div>
                          )}
                        </div>
                        <div className="mt-3 flex items-center gap-2">
                          {cert.isExpired ? (
                            <span className="badge-error">만료됨</span>
                          ) : isExpiringSoon ? (
                            <span className="badge-warning">{daysRemaining}일 후 만료</span>
                          ) : (
                            <span className="badge-success">유효</span>
                          )}
                          <span className="text-xs text-gray-400">
                            ~{formatDate(cert.notAfter)}
                          </span>
                        </div>
                      </label>
                    );
                  })
                )}
              </div>
            </div>

            {/* 비밀번호 입력 */}
            <div className="mb-6">
              <label className="label">인증서 비밀번호</label>
              <div className="relative">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input pr-12"
                  placeholder="비밀번호를 입력하세요"
                  autoComplete="current-password"
                />
                <div className="absolute right-4 top-1/2 -translate-y-1/2">
                  <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
              </div>
            </div>

            {/* 로그인 버튼 */}
            <button
              type="submit"
              disabled={!selectedCert || !password}
              className="btn-primary btn-lg w-full"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
              </svg>
              로그인
            </button>
          </form>

          {/* 하단 링크 */}
          <div className="mt-8 pt-6 border-t border-gray-100">
            <div className="flex justify-center gap-6">
              <button
                onClick={() => setShowImport(true)}
                className="flex items-center text-sm text-gray-600 hover:text-blue-600 transition-colors"
              >
                <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                </svg>
                인증서 가져오기
              </button>
              <a 
                href="/certificates/issue" 
                className="flex items-center text-sm text-gray-600 hover:text-blue-600 transition-colors"
              >
                <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                인증서 발급받기
              </a>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
