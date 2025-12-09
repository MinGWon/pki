import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';

interface Certificate {
  certId: string;
  serialNumber?: string;
  serialNumberHash?: string;
  subjectDN: string;
  issuerDN: string;
  notAfter: string;
  isExpired: boolean;
}

interface DriveInfo {
  letter: string;
  label: string;
  type: string; // 'Fixed' | 'Removable' | 'Network'
}

type Step = 'loading' | 'no-agent' | 'select' | 'signing' | 'success' | 'error';
type StorageType = 'harddisk' | 'removable' | 'token' | 'cloud';

export default function IframeAuthPage() {
  const router = useRouter();
  const { client_id: queryClientId, redirect_uri: queryRedirectUri, state: queryState, scope: queryScope, code_challenge, code_challenge_method } = router.query;

  const [step, setStep] = useState<Step>('loading');
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  const [storageType, setStorageType] = useState<StorageType>('harddisk');
  const [selectedDrive, setSelectedDrive] = useState<string>('C');
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCert, setSelectedCert] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [showDriveDropdown, setShowDriveDropdown] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // postMessage로 받은 인증 요청 정보
  const [authRequest, setAuthRequest] = useState<{
    clientId?: string;
    redirectUri?: string;
    scope?: string;
    state?: string;
  } | null>(null);

  const agentUrl = process.env.NEXT_PUBLIC_AGENT_URL || 'https://localhost:52443';
  const dropdownRef = useRef<HTMLDivElement>(null);

  // 실제 사용할 값 (postMessage 우선, URL 쿼리 fallback)
  const clientId = authRequest?.clientId || (typeof queryClientId === 'string' ? queryClientId : undefined);
  const redirectUri = authRequest?.redirectUri || (typeof queryRedirectUri === 'string' ? queryRedirectUri : undefined);
  const scope = authRequest?.scope || (typeof queryScope === 'string' ? queryScope : '');
  const state = authRequest?.state || (typeof queryState === 'string' ? queryState : undefined);

  // 이동식 드라이브만 필터링
  const removableDrives = drives.filter(d => d.type === 'Removable');

  useEffect(() => {
    // 팝업 창인지 iframe인지 확인
    const isInIframe = window.self !== window.top;
    const isPopup = window.opener !== null;
    
    console.log('[iframe] Window type:', { isInIframe, isPopup });
    
    checkAgent();
  }, []);

  // clientId 유효성 검증
  useEffect(() => {
    async function validateClient() {
      if (clientId && clientId !== 'default') {
        try {
          const res = await fetch(`/api/oauth/clients/${clientId}/validate`);
          if (!res.ok) {
            setError('유효하지 않은 클라이언트입니다.');
            setStep('error');
          }
        } catch {
          // 검증 API가 없으면 무시
        }
      }
    }
    
    if (step === 'select' && clientId) {
      validateClient();
    }
  }, [clientId, step]);

  // 부모 창에서 PKI_AUTH_REQUEST 메시지 수신
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      console.log('[iframe] Received message:', event.data);

      if (event.data?.type === 'PKI_AUTH_REQUEST' && event.data?.payload) {
        const { clientId, redirectUri, scope, state } = event.data.payload;
        console.log('[iframe] PKI_AUTH_REQUEST received:', { clientId, redirectUri, scope, state });
        
        // clientId 필수 체크
        if (!clientId) {
          setError('클라이언트 ID가 필요합니다.');
          setStep('error');
          postMessageToParent('error', { error: 'invalid_request' });
          return;
        }
        
        setAuthRequest({ clientId, redirectUri, scope, state });
      }
    }

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  useEffect(() => {
    if (step === 'select') {
      if (storageType === 'harddisk') {
        loadCertificates('C');
      } else if (storageType === 'removable' && selectedDrive) {
        loadCertificates(selectedDrive);
      } else if (storageType === 'token' || storageType === 'cloud') {
        // 더미: 인증서 없음
        setCertificates([]);
        setSelectedCert(null);
      }
    }
  }, [storageType, selectedDrive, step]);

  // 드롭다운 외부 클릭 시 닫기
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDriveDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  async function checkAgent() {
    setStep('loading');
    try {
      // Health Check 요청
      const healthRes = await fetch(`${agentUrl}/api/health`, { 
        method: 'GET', 
        mode: 'cors',
        credentials: 'omit',
      });
      
      if (!healthRes.ok) throw new Error('Agent not available');

      // 드라이브 목록 조회
      const drivesRes = await fetch(`${agentUrl}/api/drives`, { method: 'GET', mode: 'cors' });
      if (drivesRes.ok) {
        const drivesData = await drivesRes.json();
        setDrives(drivesData);
        
        // 이동식 드라이브 기본값 설정
        const removable = drivesData.filter((d: DriveInfo) => d.type === 'Removable');
        if (removable.length > 0) {
          setSelectedDrive(removable[0].letter);
        }
      }

      // 기본 하드디스크(C:)에서 인증서 로드
      await loadCertificates('C');
      setStep('select');
    } catch (err) {
      console.error('Agent connection error:', err);
      setError(err instanceof Error ? err.message : 'Agent 연결 실패');
      setStep('no-agent');
    }
  }

  async function loadCertificates(drive: string) {
    try {
      const certRes = await fetch(`${agentUrl}/api/certificates?drive=${drive}`, { method: 'GET', mode: 'cors' });
      if (!certRes.ok) throw new Error('Failed to load certificates');

      const certs = await certRes.json();
      setCertificates(certs);
      
      const firstValid = certs.find((c: Certificate) => !c.isExpired);
      setSelectedCert(firstValid ? firstValid.certId : null);
    } catch {
      setCertificates([]);
      setSelectedCert(null);
    }
  }

  function handleStorageTypeChange(type: StorageType) {
    if (type === 'removable') {
      setShowDriveDropdown(!showDriveDropdown);
      if (storageType !== 'removable') {
        setStorageType(type);
        setSelectedCert(null);
        setPassword('');
        setError(null);
        setCertificates([]); // 인증서 목록 초기화
      }
    } else {
      setShowDriveDropdown(false);
      setStorageType(type);
      setSelectedCert(null);
      setPassword('');
      setError(null);
    }
  }

  function handleDriveSelect(driveLetter: string) {
    setSelectedDrive(driveLetter);
    setShowDriveDropdown(false);
  }

  function getDriveLabel(drive: DriveInfo): string {
    if (drive.type === 'Fixed') {
      return `하드디스크 (${drive.letter}:)`;
    } else if (drive.type === 'Removable') {
      return `이동식디스크 (${drive.letter}:)`;
    } else if (drive.type === 'Network') {
      return `네트워크드라이브 (${drive.letter}:)`;
    }
    return `${drive.label || '드라이브'} (${drive.letter}:)`;
  }

  function getDriveTypeLabel(type: string): string {
    if (type === 'Fixed') return '하드디스크';
    if (type === 'Removable') return '이동식디스크';
    if (type === 'Network') return '네트워크드라이브';
    return '드라이브';
  }

  function getGroupedDrives(): { type: string; label: string; drives: DriveInfo[] }[] {
    const groups: { [key: string]: DriveInfo[] } = {};
    drives.forEach((drive) => {
      if (!groups[drive.type]) {
        groups[drive.type] = [];
      }
      groups[drive.type].push(drive);
    });

    return Object.entries(groups).map(([type, driveList]) => ({
      type,
      label: getDriveTypeLabel(type),
      drives: driveList,
    }));
  }

  function showErrorToast(message: string) {
    setToastMessage(message);
    setShowToast(true);
    setTimeout(() => {
      setShowToast(false);
    }, 2000);
  }

  async function handleSubmit() {
    if (!selectedCert || !password) {
      showErrorToast('인증서와 비밀번호를 입력해주세요.');
      return;
    }

    // 디버그: clientId, redirectUri 확인
    console.log('[iframe] handleSubmit - Auth params:', {
      clientId,
      redirectUri,
      scope,
      state,
      queryClientId,
      queryRedirectUri,
      authRequest,
    });

    setStep('signing');
    setError(null);

    try {
      // 1. 챌린지 요청
      const challengeRes = await fetch('/api/auth/challenge');
      if (!challengeRes.ok) throw new Error('챌린지 생성 실패');
      const { challenge } = await challengeRes.json();

      // 2. Agent 서명
      const signRes = await fetch(`${agentUrl}/api/certificates/${selectedCert}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: challenge, password }),
      });

      if (!signRes.ok) {
        const err = await signRes.json();
        // 비밀번호 오류인 경우 토스트로 표시
        if (err.error?.includes('password') || err.error?.includes('비밀번호') || signRes.status === 401) {
          showErrorToast('비밀번호가 올바르지 않습니다.');
          setStep('select');
          return;
        }
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

      // 4. Authorization Code 생성 (clientId/redirectUri 없어도 생성)
      const codeRes = await fetch('/api/auth/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: user.id,
          clientId: clientId || 'default',
          redirectUri: redirectUri || 'postmessage',
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

      setStep('success');
      postMessageToParent('success', { code });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : '인증 중 오류 발생';
      if (errorMessage.includes('password') || errorMessage.includes('비밀번호')) {
        showErrorToast(errorMessage);
        setStep('select');
      } else {
        setError(errorMessage);
        setStep('error');
      }
    }
  }

  function handleCancel() {
    postMessageToParent('error', { error: 'access_denied' });
  }

  function postMessageToParent(type: 'success' | 'error', data: { code?: string; error?: string }) {
    const isInIframe = window.self !== window.top;
    const isPopup = window.opener !== null;
    
    if (isPopup && window.opener) {
      // 팝업인 경우 opener에게 메시지 전송
      const message = type === 'success' 
        ? {
            type: 'PKI_AUTH_RESPONSE',
            payload: {
              code: data.code,
              state: state || null,
            }
          }
        : {
            type: 'PKI_AUTH_ERROR',
            payload: {
              error: data.error || 'unknown_error',
              state: state || null,
            }
          };
      
      console.log('[popup] Sending postMessage to opener:', message);
      window.opener.postMessage(message, '*');
      
      // 2초 후 팝업 창 닫기
      setTimeout(() => {
        window.close();
      }, 2000);
    } else if (isInIframe && window.parent !== window) {
      // iframe인 경우 parent에게 메시지 전송
      const message = type === 'success' 
        ? {
            type: 'PKI_AUTH_RESPONSE',
            payload: {
              code: data.code,
              state: state || null,
            }
          }
        : {
            type: 'PKI_AUTH_ERROR',
            payload: {
              error: data.error || 'unknown_error',
              state: state || null,
            }
          };
      
      console.log('[iframe] Sending postMessage to parent:', message);
      window.parent.postMessage(message, '*');
    } else {
      console.log('[standalone] Not in iframe or popup');
    }
  }

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString('ko-KR');
  }

  function extractCN(dn: string): string {
    const match = dn.match(/CN=([^,]+)/);
    if (!match) return dn;
    
    const cn = match[1].trim();
    
    // B64_ 접두사가 있으면 Base64 디코딩
    if (cn.startsWith('B64_')) {
      try {
        const base64 = cn.substring(4);
        return decodeURIComponent(escape(atob(base64)));
      } catch {
        return cn;
      }
    }
    
    return cn;
  }

  function formatIssuer(dn: string): string {
    const cn = extractCN(dn);
    if (cn === '2Check Intermediate CA') {
      return '인증센터';
    }
    return cn;
  }

  const storageOptions: { type: StorageType; label: string; icon: React.ReactElement; disabled?: boolean }[] = [
    {
      type: 'harddisk',
      label: '하드디스크',
      icon: (
        <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <path d="M4 15h16" />
          <circle cx="7" cy="18" r="1" fill="currentColor" />
        </svg>
      ),
    },
    {
      type: 'removable',
      label: '이동식디스크',
      icon: (
        <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
          <rect x="6" y="4" width="12" height="16" rx="1" />
          <path d="M9 4V2h6v2" />
          <path d="M6 8h12" />
        </svg>
      ),
    },
    {
      type: 'token',
      label: '보안토큰',
      icon: (
        <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
          <rect x="5" y="10" width="14" height="8" rx="2" />
          <path d="M12 6v4" />
          <circle cx="12" cy="5" r="2" />
        </svg>
      ),
      disabled: true,
    },
    {
      type: 'cloud',
      label: '클라우드',
      icon: (
        <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
          <path d="M19 18H6a4 4 0 01-.5-7.97A6.002 6.002 0 0117.66 8.5a5 5 0 011.34 9.5z" />
        </svg>
      ),
      disabled: true,
    },
  ];

  return (
    <>
      <Head>
        <title>인증서 로그인 - 2Check PKI</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>

      {/* Toast 알림 */}
      {showToast && (
        <div style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          backgroundColor: '#1f2937',
          color: 'white',
          padding: '24px 40px',
          borderRadius: '12px',
          boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
          zIndex: 1100,
          minWidth: '320px',
          maxWidth: '450px',
          textAlign: 'center',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', marginBottom: '16px' }}>
            <svg width="24" height="24" fill="none" stroke="#f87171" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span style={{ fontSize: '16px', fontWeight: '500' }}>{toastMessage}</span>
          </div>
          {/* 쿨다운 바 */}
          <div style={{ 
            height: '3px', 
            backgroundColor: 'rgba(255,255,255,0.2)', 
            borderRadius: '3px', 
            overflow: 'hidden',
            width: '270px',
          }}>
            <div style={{
              height: '100%',
              backgroundColor: '#f87171',
              animation: 'cooldown 2s linear forwards',
            }} />
          </div>
          <style>{`
            @keyframes cooldown {
              from { width: 100%; }
              to { width: 0%; }
            }
          `}</style>
        </div>
      )}

      <div style={{ minHeight: '100vh', backgroundColor: '#f9fafb', display: 'flex', flexDirection: 'column', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', boxSizing: 'border-box' }}>
        {/* Header */}


        {/* Content */}
        <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
          <div style={{ maxWidth: '560px', margin: '0 auto' }}>
            {step === 'loading' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '40px 20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', textAlign: 'center' }}>
                <div style={{ width: '40px', height: '40px', border: '3px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto 16px', animation: 'spin 1s linear infinite' }} />
                <p style={{ color: '#6b7280', fontSize: '14px' }}>Agent 연결 중...</p>
                <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
              </div>
            )}

            {step === 'no-agent' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', textAlign: 'center' }}>
                <div style={{ width: '56px', height: '56px', backgroundColor: '#fef3c7', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                  <svg width="28" height="28" fill="none" stroke="#d97706" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: 'bold', marginBottom: '8px' }}>Agent 연결 실패</h3>
                <p style={{ color: '#6b7280', fontSize: '13px', marginBottom: '12px' }}>
                  2Check Agent가 실행 중인지 확인해주세요.
                </p>
                
                {error && (
                  <div style={{ backgroundColor: '#fee2e2', padding: '8px 12px', borderRadius: '6px', marginBottom: '12px', fontSize: '11px', color: '#991b1b', fontFamily: 'monospace', textAlign: 'left', wordBreak: 'break-word' }}>
                    {error}
                  </div>
                )}

                <div style={{ backgroundColor: '#fef3c7', padding: '12px', borderRadius: '8px', marginBottom: '12px', fontSize: '12px', textAlign: 'left' }}>
                  <p style={{ color: '#92400e', marginBottom: '8px', fontWeight: '500' }}>확인사항:</p>
                  <ul style={{ color: '#92400e', paddingLeft: '20px', margin: 0, lineHeight: '1.6' }}>
                    <li>Agent가 설치되어 실행 중인가요?</li>
                    <li>방화벽이 52443 포트를 차단하고 있나요?</li>
                    <li>자체 서명 인증서를 신뢰했나요?</li>
                  </ul>
                </div>
                
                <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                  <a href="/download/agent" target="_blank" style={{ padding: '10px 20px', backgroundColor: '#2563eb', color: 'white', borderRadius: '8px', textDecoration: 'none', fontSize: '13px', fontWeight: '500' }}>Agent 다운로드</a>
                  <button onClick={checkAgent} style={{ padding: '10px 20px', backgroundColor: 'white', border: '1px solid #d1d5db', borderRadius: '8px', cursor: 'pointer', fontSize: '13px' }}>다시 시도</button>
                </div>
              </div>
            )}

            {step === 'select' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
                {error && (
                  <div style={{ padding: '10px', backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '16px', color: '#dc2626', fontSize: '13px' }}>
                    {error}
                  </div>
                )}

                {/* 저장소 유형 선택 */}
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '500', marginBottom: '8px', color: '#374151' }}>인증서 위치</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
                    {storageOptions.map((option) => (
                      <div key={option.type} style={{ position: 'relative' }} ref={option.type === 'removable' ? dropdownRef : undefined}>
                        <button
                          onClick={() => !option.disabled && handleStorageTypeChange(option.type)}
                          disabled={option.disabled}
                          style={{
                            width: '100%',
                            padding: '12px 8px',
                            borderRadius: '8px',
                            border: storageType === option.type ? '2px solid #2563eb' : '1px solid #d1d5db',
                            backgroundColor: option.disabled ? '#f3f4f6' : storageType === option.type ? '#eff6ff' : 'white',
                            color: option.disabled ? '#9ca3af' : storageType === option.type ? '#2563eb' : '#374151',
                            fontSize: '11px',
                            fontWeight: storageType === option.type ? '600' : '400',
                            cursor: option.disabled ? 'not-allowed' : 'pointer',
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            gap: '6px',
                            opacity: option.disabled ? 0.6 : 1,
                          }}
                        >
                          {option.icon}
                          <span style={{ whiteSpace: 'pre-line', textAlign: 'center', lineHeight: '1.3' }}>
                            {option.label}
                          </span>                        </button>

                        {/* 이동식디스크 드롭다운 */}
                        {option.type === 'removable' && showDriveDropdown && (
                          <div style={{
                            position: 'absolute',
                            top: '100%',
                            left: '50%',
                            transform: 'translateX(-50%)',
                            marginTop: '4px',
                            backgroundColor: 'white',
                            border: '1px solid #e5e7eb',
                            borderRadius: '8px',
                            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                            zIndex: 100,
                            minWidth: '140px',
                            overflow: 'hidden',
                          }}>
                            <div style={{ padding: '8px 12px', backgroundColor: '#f9fafb', borderBottom: '1px solid #e5e7eb', fontSize: '11px', color: '#6b7280', fontWeight: '500' }}>
                              드라이브 선택
                            </div>
                            {removableDrives.length === 0 ? (
                              <div style={{ padding: '12px', fontSize: '12px', color: '#9ca3af', textAlign: 'center' }}>
                                이동식 디스크 없음
                              </div>
                            ) : (
                              removableDrives.map((drive) => (
                                <button
                                  key={drive.letter}
                                  onClick={() => handleDriveSelect(drive.letter)}
                                  style={{
                                    width: '100%',
                                    padding: '10px 12px',
                                    border: 'none',
                                    backgroundColor: selectedDrive === drive.letter ? '#eff6ff' : 'white',
                                    color: selectedDrive === drive.letter ? '#2563eb' : '#374151',
                                    fontSize: '13px',
                                    fontWeight: selectedDrive === drive.letter ? '600' : '400',
                                    cursor: 'pointer',
                                    textAlign: 'left',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '8px',
                                    borderBottom: '1px solid #f3f4f6',
                                  }}
                                >
                                  <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
                                    <rect x="6" y="4" width="12" height="16" rx="1" />
                                    <path d="M9 4V2h6v2" />
                                  </svg>
                                  {drive.letter}: {drive.label || '이동식 디스크'}
                                </button>
                              ))
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* 보안토큰/클라우드 준비중 메시지 */}
                {(storageType === 'token' || storageType === 'cloud') && (
                  <div style={{ marginBottom: '16px', padding: '24px', backgroundColor: '#f9fafb', borderRadius: '8px', textAlign: 'center' }}>
                    <p style={{ fontSize: '14px', color: '#6b7280' }}>
                      {storageType === 'token' ? '보안토큰' : '클라우드'} 인증서는 준비 중입니다.
                    </p>
                  </div>
                )}

                {/* 인증서 목록 */}
                {(storageType === 'harddisk' || storageType === 'removable') && (
                  <>
                    {certificates.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '24px', backgroundColor: '#f9fafb', borderRadius: '8px' }}>
                        <p style={{ color: '#6b7280', fontSize: '13px' }}>저장된 인증서가 없습니다.</p>
                      </div>
                    ) : (
                      <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', overflow: 'hidden' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                          <thead>
                            <tr style={{ backgroundColor: '#f9fafb' }}>
                              <th style={{ padding: '6px 6px', textAlign: 'center', borderBottom: '1px solid #e5e7eb', borderRight: '1px solid #e5e7eb', width: '32px' }}>
                                <svg width="16" height="16" fill="none" stroke="#6b7280" strokeWidth="2" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                              </th>
                              <th style={{ padding: '6px 6px', textAlign: 'left', borderBottom: '1px solid #e5e7eb', borderRight: '1px solid #e5e7eb', fontWeight: '600', color: '#374151' }}>이름</th>
                              <th style={{ padding: '6px 6px', textAlign: 'left', borderBottom: '1px solid #e5e7eb', borderRight: '1px solid #e5e7eb', fontWeight: '600', color: '#374151' }}>발급자</th>
                              <th style={{ padding: '6px 6px', textAlign: 'left', borderBottom: '1px solid #e5e7eb', fontWeight: '600', color: '#374151' }}>만료일</th>
                            </tr>
                          </thead>
                          <tbody>
                            {certificates.map((cert, index) => (
                              <tr
                                key={cert.certId}
                                onClick={() => !cert.isExpired && setSelectedCert(cert.certId)}
                                style={{
                                  cursor: cert.isExpired ? 'not-allowed' : 'pointer',
                                  backgroundColor: selectedCert === cert.certId ? '#eff6ff' : 'white',
                                  opacity: cert.isExpired ? 0.5 : 1,
                                  borderBottom: index < certificates.length - 1 ? '1px solid #f3f4f6' : 'none',
                                  transition: 'background-color 0.15s',
                                }}
                              >
                                <td style={{ padding: '6px 6px', textAlign: 'center', borderRight: '1px solid #e5e7eb' }}>
                                  {cert.isExpired ? (
                                    <svg width="16" height="16" fill="none" stroke="#dc2626" strokeWidth="2" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                    </svg>
                                  ) : (
                                    <svg width="16" height="16" fill="none" stroke={selectedCert === cert.certId ? '#2563eb' : '#16a34a'} strokeWidth="2" viewBox="0 0 24 24">
                                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                  )}
                                </td>
                                <td style={{ padding: '6px 6px', borderRight: '1px solid #e5e7eb', fontWeight: '500', color: selectedCert === cert.certId ? '#2563eb' : '#111827', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {extractCN(cert.subjectDN)}
                                </td>
                                <td style={{ padding: '6px 6px', borderRight: '1px solid #e5e7eb', color: '#6b7280', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {formatIssuer(cert.issuerDN)}
                                </td>
                                <td style={{ padding: '6px 6px', color: '#6b7280' }}>
                                  {formatDate(cert.notAfter)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {step === 'signing' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '40px 20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', textAlign: 'center' }}>
                <div style={{ width: '40px', height: '40px', border: '3px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto 16px', animation: 'spin 1s linear infinite' }} />
                <p style={{ color: '#6b7280', fontSize: '14px' }}>인증 중...</p>
              </div>
            )}

            {step === 'success' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', textAlign: 'center' }}>
                <div style={{ width: '56px', height: '56px', backgroundColor: '#dcfce7', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                  <svg width="28" height="28" fill="none" stroke="#16a34a" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: 'bold', marginBottom: '8px' }}>인증 성공!</h3>
                <p style={{ color: '#6b7280', fontSize: '13px' }}>잠시 후 이동합니다...</p>
              </div>
            )}

            {step === 'error' && (
              <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '20px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', textAlign: 'center' }}>
                <div style={{ width: '56px', height: '56px', backgroundColor: '#fef2f2', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                  <svg width="28" height="28" fill="none" stroke="#dc2626" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: 'bold', marginBottom: '8px' }}>인증 실패</h3>
                <p style={{ color: '#dc2626', fontSize: '13px', marginBottom: '20px' }}>{error}</p>
                <button onClick={() => setStep('select')} style={{ padding: '10px 24px', backgroundColor: 'white', border: '1px solid #d1d5db', borderRadius: '8px', cursor: 'pointer', fontSize: '13px' }}>
                  다시 시도
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        {step === 'select' && certificates.length > 0 && (storageType === 'harddisk' || storageType === 'removable') && (
          <div style={{ padding: '16px', borderTop: '1px solid #e5e7eb', backgroundColor: 'white' }}>
            <div style={{ maxWidth: '560px', margin: '0 auto' }}>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '500', marginBottom: '6px' }}>인증서 비밀번호</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  placeholder="비밀번호를 입력하세요"
                  autoFocus
                />
              </div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button onClick={handleCancel} style={{ flex: 1, padding: '12px', backgroundColor: 'white', color: '#374151', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', cursor: 'pointer' }}>
                  취소
                </button>
                <button onClick={handleSubmit} disabled={!selectedCert || !password} style={{ flex: 2, padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', opacity: (!selectedCert || !password) ? 0.5 : 1 }}>
                  로그인
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
