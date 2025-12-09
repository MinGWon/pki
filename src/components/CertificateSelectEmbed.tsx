import { useState, useEffect } from 'react';

interface Certificate {
  certId: string;
  serialNumber?: string;
  serialNumberHash?: string;
  subjectDN: string;
  issuerDN: string;
  notBefore?: string;
  notAfter: string;
  isExpired: boolean;
}

interface CertificateSelectEmbedProps {
  onSelect: (result: { certId: string; serialNumber: string; signature: string; userId?: string; user?: any }) => void;
  onCancel?: () => void;
  title?: string;
  description?: string;
  challengeEndpoint?: string;
  verifyEndpoint?: string;
  skipVerify?: boolean;
}

type Step = 'loading' | 'no-agent' | 'select' | 'signing' | 'success' | 'error';

export default function CertificateSelectEmbed({
  onSelect,
  onCancel,
  title = '인증서 선택',
  description = '사용할 인증서를 선택하세요.',
  challengeEndpoint = '/api/auth/challenge',
  verifyEndpoint = '/api/auth/signature/verify',
  skipVerify = false,
}: CertificateSelectEmbedProps) {
  const [step, setStep] = useState<Step>('loading');
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCert, setSelectedCert] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const agentUrl = process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:52080';

  useEffect(() => {
    checkAgent();
  }, []);

  async function checkAgent() {
    setStep('loading');
    setCertificates([]);
    setSelectedCert(null);
    setPassword('');
    setError(null);

    try {
      const healthRes = await fetch(`${agentUrl}/api/health`, { method: 'GET', mode: 'cors' });
      if (!healthRes.ok) throw new Error('Agent not available');

      const certRes = await fetch(`${agentUrl}/api/certificates`, { method: 'GET', mode: 'cors' });
      if (!certRes.ok) throw new Error('Failed to load certificates');

      const data = await certRes.json();
      setCertificates(data);
      setStep('select');
    } catch {
      setStep('no-agent');
    }
  }

  async function handleSubmit() {
    if (!selectedCert || !password) {
      setError('인증서와 비밀번호를 입력해주세요.');
      return;
    }

    setStep('signing');
    setError(null);

    try {
      const challengeRes = await fetch(challengeEndpoint);
      if (!challengeRes.ok) throw new Error('챌린지 생성 실패');
      const { challenge } = await challengeRes.json();

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

      if (skipVerify) {
        onSelect({ certId: selectedCert, serialNumber, signature });
        return;
      }

      const verifyRes = await fetch(verifyEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge, signature, certificateSerialNumber: serialNumber }),
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json();
        throw new Error(err.error || '인증 실패');
      }

      const verifyData = await verifyRes.json();
      setStep('success');

      setTimeout(() => {
        onSelect({
          certId: selectedCert,
          serialNumber,
          signature,
          userId: verifyData.user?.id,
          user: verifyData.user,
        });
      }, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : '인증 중 오류 발생');
      setStep('error');
    }
  }

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString('ko-KR');
  }

  function extractCN(dn: string): string {
    const match = dn.match(/CN=([^,]+)/);
    return match ? match[1] : dn;
  }

  const containerStyle: React.CSSProperties = {
    minHeight: '100%',
    backgroundColor: '#f9fafb',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  };

  const cardStyle: React.CSSProperties = {
    backgroundColor: 'white',
    borderRadius: '12px',
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
    padding: '24px',
    maxWidth: '600px',
    margin: '0 auto',
  };

  const buttonStyle: React.CSSProperties = {
    width: '100%',
    padding: '12px',
    backgroundColor: '#2563eb',
    color: 'white',
    border: 'none',
    borderRadius: '8px',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
  };

  return (
    <div style={containerStyle}>
      <div style={cardStyle}>
        {/* Header */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <div style={{ width: '40px', height: '40px', backgroundColor: '#2563eb', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <svg width="20" height="20" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827', margin: 0 }}>{title}</h1>
              <p style={{ fontSize: '14px', color: '#6b7280', margin: 0 }}>2Check PKI</p>
            </div>
          </div>
        </div>

        {/* Content */}
        {step === 'loading' && (
          <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <div style={{ width: '48px', height: '48px', border: '4px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto 24px', animation: 'spin 1s linear infinite' }} />
            <p style={{ color: '#6b7280' }}>Agent 연결 중...</p>
            <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {step === 'no-agent' && (
          <div style={{ textAlign: 'center', padding: '24px 0' }}>
            <div style={{ width: '64px', height: '64px', backgroundColor: '#fef3c7', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
              <svg width="32" height="32" fill="none" stroke="#d97706" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '8px' }}>Agent가 필요합니다</h3>
            <p style={{ color: '#6b7280', fontSize: '14px', marginBottom: '24px' }}>인증서 로그인을 위해 2Check Agent를 설치해주세요.</p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <a href="/download/agent" target="_blank" style={{ ...buttonStyle, width: 'auto', padding: '12px 24px', textDecoration: 'none' }}>Agent 다운로드</a>
              <button onClick={checkAgent} style={{ ...buttonStyle, width: 'auto', padding: '12px 24px', backgroundColor: 'white', color: '#374151', border: '1px solid #d1d5db' }}>다시 시도</button>
            </div>
          </div>
        )}

        {step === 'select' && (
          <>
            {error && (
              <div style={{ padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '16px', color: '#dc2626', fontSize: '14px' }}>
                {error}
              </div>
            )}

            <p style={{ color: '#6b7280', fontSize: '14px', marginBottom: '16px' }}>{description}</p>

            {certificates.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px', backgroundColor: '#f9fafb', borderRadius: '8px', marginBottom: '16px' }}>
                <p style={{ color: '#6b7280' }}>저장된 인증서가 없습니다.</p>
              </div>
            ) : (
              <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', overflow: 'hidden', marginBottom: '16px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
                  <thead>
                    <tr>
                      <th style={{ padding: '12px 8px', textAlign: 'left', borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb', width: '40px' }}></th>
                      <th style={{ padding: '12px 8px', textAlign: 'left', borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb' }}>이름</th>
                      <th style={{ padding: '12px 8px', textAlign: 'left', borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb' }}>만료일</th>
                      <th style={{ padding: '12px 8px', textAlign: 'left', borderBottom: '2px solid #e5e7eb', backgroundColor: '#f9fafb', width: '60px' }}>상태</th>
                    </tr>
                  </thead>
                  <tbody>
                    {certificates.map((cert) => (
                      <tr
                        key={cert.certId}
                        onClick={() => !cert.isExpired && setSelectedCert(cert.certId)}
                        style={{
                          cursor: cert.isExpired ? 'not-allowed' : 'pointer',
                          backgroundColor: selectedCert === cert.certId ? '#eff6ff' : 'transparent',
                          opacity: cert.isExpired ? 0.5 : 1,
                        }}
                      >
                        <td style={{ padding: '12px 8px', borderBottom: '1px solid #e5e7eb' }}>
                          <input type="radio" name="certificate" checked={selectedCert === cert.certId} onChange={() => setSelectedCert(cert.certId)} disabled={cert.isExpired} />
                        </td>
                        <td style={{ padding: '12px 8px', borderBottom: '1px solid #e5e7eb', fontWeight: '500' }}>{extractCN(cert.subjectDN)}</td>
                        <td style={{ padding: '12px 8px', borderBottom: '1px solid #e5e7eb', color: '#6b7280' }}>{formatDate(cert.notAfter)}</td>
                        <td style={{ padding: '12px 8px', borderBottom: '1px solid #e5e7eb' }}>
                          <span style={{ padding: '2px 8px', borderRadius: '9999px', fontSize: '12px', backgroundColor: cert.isExpired ? '#fef2f2' : '#dcfce7', color: cert.isExpired ? '#dc2626' : '#16a34a' }}>
                            {cert.isExpired ? '만료' : '유효'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>인증서 비밀번호</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                style={{ width: '100%', padding: '12px 16px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                placeholder="비밀번호를 입력하세요"
              />
            </div>

            <div style={{ display: 'flex', gap: '12px' }}>
              {onCancel && (
                <button onClick={onCancel} style={{ ...buttonStyle, flex: 1, backgroundColor: 'white', color: '#374151', border: '1px solid #d1d5db' }}>
                  취소
                </button>
              )}
              <button onClick={handleSubmit} disabled={!selectedCert || !password} style={{ ...buttonStyle, flex: 2, opacity: (!selectedCert || !password) ? 0.5 : 1 }}>
                확인
              </button>
            </div>
          </>
        )}

        {step === 'signing' && (
          <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <div style={{ width: '48px', height: '48px', border: '4px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto 24px', animation: 'spin 1s linear infinite' }} />
            <p style={{ color: '#6b7280' }}>인증서로 서명 중...</p>
          </div>
        )}

        {step === 'success' && (
          <div style={{ textAlign: 'center', padding: '24px 0' }}>
            <div style={{ width: '80px', height: '80px', backgroundColor: '#dcfce7', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
              <svg width="40" height="40" fill="none" stroke="#16a34a" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h3 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '8px' }}>인증 성공!</h3>
            <p style={{ color: '#6b7280', fontSize: '14px' }}>잠시 후 이동합니다...</p>
          </div>
        )}

        {step === 'error' && (
          <div style={{ textAlign: 'center', padding: '24px 0' }}>
            <div style={{ width: '64px', height: '64px', backgroundColor: '#fef2f2', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
              <svg width="32" height="32" fill="none" stroke="#dc2626" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '8px' }}>인증 실패</h3>
            <p style={{ color: '#dc2626', fontSize: '14px', marginBottom: '24px' }}>{error}</p>
            <button onClick={() => setStep('select')} style={{ ...buttonStyle, backgroundColor: 'white', color: '#374151', border: '1px solid #d1d5db' }}>다시 시도</button>
          </div>
        )}
      </div>
    </div>
  );
}
