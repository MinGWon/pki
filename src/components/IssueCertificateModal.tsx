import React, { useState, useEffect, useRef } from 'react';
import { formatPhoneNumber } from '@/lib/format';

interface DriveInfo {
  letter: string;
  label: string;
  type: string;
}

type Step = 'form' | 'sms-sent' | 'password' | 'issuing' | 'complete';
type StorageType = 'harddisk' | 'removable' | 'token' | 'cloud';

interface IssueCertificateModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function IssueCertificateModal({ isOpen, onClose }: IssueCertificateModalProps) {
  const [step, setStep] = useState<Step>('form');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // 폼 데이터
  const [formData, setFormData] = useState({ name: '', email: '', phone: '' });
  const [verificationCode, setVerificationCode] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [userId, setUserId] = useState<string | null>(null);

  // 저장 위치
  const [storageType, setStorageType] = useState<StorageType>('harddisk');
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  const [selectedDrive, setSelectedDrive] = useState<string>('C');
  const [showDriveDropdown, setShowDriveDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const agentUrl = process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:52080';
  const removableDrives = drives.filter(d => d.type === 'Removable');

  // SMS 관련 상태
  const [smsCode, setSmsCode] = useState('');
  const [smsSending, setSmsSending] = useState(false);
  const [smsTimer, setSmsTimer] = useState(0);
  const [devCode, setDevCode] = useState<string | null>(null); // 개발용

  useEffect(() => {
    if (isOpen) {
      loadDrives();
    }
  }, [isOpen]);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDriveDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // SMS 타이머
  useEffect(() => {
    if (smsTimer > 0) {
      const timer = setTimeout(() => setSmsTimer(smsTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [smsTimer]);

  async function loadDrives() {
    try {
      const res = await fetch(`${agentUrl}/api/drives`, { method: 'GET', mode: 'cors' });
      if (res.ok) {
        const data = await res.json();
        setDrives(data);
        const removable = data.filter((d: DriveInfo) => d.type === 'Removable');
        if (removable.length > 0) {
          setSelectedDrive(removable[0].letter);
        }
      }
    } catch {
      // Agent 없으면 무시
    }
  }

  function handleStorageTypeChange(type: StorageType) {
    if (type === 'removable') {
      setShowDriveDropdown(!showDriveDropdown);
      if (storageType !== 'removable') {
        setStorageType(type);
      }
    } else {
      setShowDriveDropdown(false);
      setStorageType(type);
    }
  }

  async function handleFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // 개발 환경: SMS 인증 우회
      const skipSmsVerification = true; // TODO: 프로덕션에서는 false로 변경

      if (skipSmsVerification) {
        // SMS 인증 없이 바로 사용자 등록
        const registerRes = await fetch('/api/users/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(formData),
        });

        const registerData = await registerRes.json();
        if (!registerRes.ok) throw new Error(registerData.error || '등록 실패');

        setUserId(registerData.user.id);
        setStep('password');
      } else {
        // SMS 인증 코드 발송
        setSmsSending(true);
        const res = await fetch('/api/auth/sms/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone: formData.phone }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'SMS 발송 실패');

        if (data.code) {
          setDevCode(data.code);
        }

        setSmsTimer(180);
        setStep('sms-sent');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '오류 발생');
    } finally {
      setLoading(false);
      setSmsSending(false);
    }
  }

  async function handleSmsVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/sms/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: formData.phone, code: smsCode }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '인증 실패');

      // 사용자 등록
      const registerRes = await fetch('/api/users/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const registerData = await registerRes.json();
      if (!registerRes.ok) throw new Error(registerData.error || '등록 실패');

      setUserId(registerData.user.id);
      setStep('password');  // 'sms-verify' → 'password'
    } catch (err) {
      setError(err instanceof Error ? err.message : '오류 발생');
    } finally {
      setLoading(false);
    }
  }

  async function handleResendSms() {
    setSmsSending(true);
    setError(null);

    try {
      const res = await fetch('/api/auth/sms/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: formData.phone }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'SMS 발송 실패');

      if (data.code) {
        setDevCode(data.code);
      }

      setSmsTimer(180);
      setSmsCode('');
    } catch (err) {
      setError(err instanceof Error ? err.message : '오류 발생');
    } finally {
      setSmsSending(false);
    }
  }

  function showErrorToast(message: string) {
    setToastMessage(message);
    setShowToast(true);
    setTimeout(() => {
      setShowToast(false);
    }, 1500);
  }

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      showErrorToast('비밀번호는 8자 이상이어야 합니다.');
      return;
    }
    if (password !== passwordConfirm) {
      showErrorToast('비밀번호가 일치하지 않습니다.');
      return;
    }

    setStep('issuing');
    setLoading(true);

    try {
      // 1. Agent 연결 확인
      const healthRes = await fetch(`${agentUrl}/api/health`, { method: 'GET', mode: 'cors' }).catch(() => null);
      if (!healthRes || !healthRes.ok) {
        throw new Error('Agent가 실행되지 않았습니다. Agent를 먼저 실행해주세요.');
      }

      // 2. 인증서 발급
      const issueRes = await fetch('/api/certificates/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          commonName: formData.name,
          name: formData.name,
          email: formData.email,
          phone: formData.phone,
          password,
        }),
      });

      const issueData = await issueRes.json();
      if (!issueRes.ok) throw new Error(issueData.error || '인증서 발급 실패');
      if (!issueData.p12) throw new Error('인증서 데이터가 없습니다.');

      // 3. Agent로 저장 (POST /api/certificates)
      const saveDrive = storageType === 'harddisk' ? 'C' : selectedDrive;
      
      // 반드시 formData.name (원본 한글)을 사용!
      const originalName = formData.name;
      const subjectDNWithKorean = `CN=${originalName}, O=2Check, C=KR`;
      
      console.log('[issue] 원본 이름:', originalName);
      console.log('[issue] subjectDN:', subjectDNWithKorean);

      const saveRes = await fetch(`${agentUrl}/api/certificates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },  // charset 명시
        mode: 'cors',
        body: JSON.stringify({
          p12Base64: issueData.p12,
          drive: saveDrive,
          metadata: {
            serialNumber: issueData.certificate.serialNumber,
            subjectDN: subjectDNWithKorean,  // formData.name 사용!
            issuerDN: issueData.certificate.issuerDN,
            notBefore: issueData.certificate.notBefore,
            notAfter: issueData.certificate.notAfter,
            displayName: originalName,  // 원본 한글
          },
        }),
      });

      if (!saveRes.ok) {
        const saveErr = await saveRes.json();
        throw new Error(saveErr.error || '인증서 저장 실패');
      }

      setStep('complete');
    } catch (err) {
      console.error('[issue] 오류:', err);
      const errorMessage = err instanceof Error ? err.message : '오류 발생';
      
      // 비밀번호 관련 오류인 경우 토스트로 표시
      if (errorMessage.includes('password') || errorMessage.includes('비밀번호')) {
        showErrorToast(errorMessage);
        setStep('password');
      } else {
        setError(errorMessage);
        setStep('password');
      }
    } finally {
      setLoading(false);
    }
  }

  function handleClose() {
    setStep('form');
    setFormData({ name: '', email: '', phone: '' });
    setVerificationCode('');
    setPassword('');
    setPasswordConfirm('');
    setError(null);
    setUserId(null);
    onClose();
  }

  if (!isOpen) return null;

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
    <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      {/* Toast 알림 */}
      {showToast && (
        <div style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          backgroundColor: '#1f2937',
          color: 'white',
          padding: '16px 24px',
          borderRadius: '12px',
          boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
          zIndex: 1100,
          minWidth: '200px',
          textAlign: 'center',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '12px' }}>
            <svg width="20" height="20" fill="none" stroke="#f87171" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span style={{ fontSize: '14px', fontWeight: '500' }}>{toastMessage}</span>
          </div>
          {/* 쿨다운 바 */}
          <div style={{ 
            height: '3px', 
            backgroundColor: 'rgba(255,255,255,0.2)', 
            borderRadius: '2px', 
            overflow: 'hidden' 
          }}>
            <div style={{
              height: '100%',
              backgroundColor: '#f87171',
              animation: 'cooldown 1.5s linear forwards',
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

      <div style={{ backgroundColor: 'white', borderRadius: '16px', width: '100%', maxWidth: '480px', maxHeight: '90vh', overflow: 'auto', boxShadow: '0 25px 50px rgba(0,0,0,0.25)' }}>
        {/* Header */}
        <div style={{ padding: '20px 24px', borderBottom: '1px solid #e5e7eb', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 'bold', margin: 0 }}>인증서 발급</h2>
          <button onClick={handleClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}>
            <svg width="24" height="24" fill="none" stroke="#6b7280" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Progress */}
        <div style={{ padding: '16px 24px', borderBottom: '1px solid #f3f4f6' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            {['정보입력', '본인인증', '비밀번호', '완료'].map((label, idx) => {
              const steps: Step[] = ['form', 'sms-sent', 'password', 'complete'];
              const currentIdx = steps.indexOf(step);
              const isActive = step === 'issuing' ? idx <= 2 : currentIdx >= idx;
              return (
                <div key={label} style={{ display: 'flex', alignItems: 'center' }}>
                  <div style={{
                    width: '28px', height: '28px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '12px', fontWeight: '600',
                    backgroundColor: isActive ? '#2563eb' : '#e5e7eb',
                    color: isActive ? 'white' : '#9ca3af',
                  }}>
                    {idx + 1}
                  </div>
                  {idx < 3 && <div style={{ width: '24px', height: '2px', backgroundColor: '#e5e7eb', margin: '0 4px' }} />}
                </div>
              );
            })}
          </div>
        </div>

        {/* Content */}
        <div style={{ padding: '24px' }}>
          {error && (
            <div style={{ padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '16px', color: '#dc2626', fontSize: '14px' }}>
              {error}
            </div>
          )}

          {/* Step 1: 정보 입력 */}
          {step === 'form' && (
            <form onSubmit={handleFormSubmit}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>이름</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  required
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>이메일</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  required
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>휴대폰</label>
                <input
                  type="tel"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: formatPhoneNumber(e.target.value) })}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  placeholder="010-0000-0000"
                  required
                />
              </div>
              <button type="submit" disabled={loading} style={{ width: '100%', padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', opacity: loading ? 0.5 : 1 }}>
                {loading ? '처리 중...' : '다음'}
              </button>
            </form>
          )}

          {/* Step 2: SMS 인증 */}
          {step === 'sms-sent' && (
            <form onSubmit={handleSmsVerify}>
              <p style={{ color: '#6b7280', marginBottom: '16px', fontSize: '14px' }}>
                {formData.phone}로 인증 코드가 발송되었습니다.
              </p>
              
              {/* 개발 환경 코드 표시 */}
              {devCode && (
                <div style={{ padding: '8px 12px', backgroundColor: '#fef3c7', borderRadius: '6px', marginBottom: '12px', fontSize: '12px', color: '#92400e' }}>
                  개발 환경: 인증 코드는 <strong>{devCode}</strong>
                </div>
              )}
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>인증 코드</label>
                <input
                  type="text"
                  value={smsCode}
                  onChange={(e) => setSmsCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '20px', textAlign: 'center', letterSpacing: '8px', boxSizing: 'border-box' }}
                  maxLength={6}
                  placeholder="000000"
                  autoFocus
                />
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px' }}>
                  <span style={{ fontSize: '12px', color: smsTimer > 0 ? '#6b7280' : '#dc2626' }}>
                    {smsTimer > 0 ? `${Math.floor(smsTimer / 60)}:${(smsTimer % 60).toString().padStart(2, '0')} 남음` : '만료됨'}
                  </span>
                  <button
                    type="button"
                    onClick={handleResendSms}
                    disabled={smsSending || smsTimer > 150}
                    style={{ fontSize: '12px', color: '#2563eb', background: 'none', border: 'none', cursor: 'pointer', opacity: smsSending || smsTimer > 150 ? 0.5 : 1 }}
                  >
                    {smsSending ? '발송 중...' : '다시 받기'}
                  </button>
                </div>
              </div>
              
              <button 
                type="submit" 
                disabled={loading || smsCode.length !== 6}
                style={{ width: '100%', padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', opacity: loading || smsCode.length !== 6 ? 0.5 : 1 }}
              >
                {loading ? '확인 중...' : '확인'}
              </button>
            </form>
          )}

          {/* Step 3: 비밀번호 & 저장 위치 */}
          {step === 'password' && (
            <form onSubmit={handlePasswordSubmit}>
              {/* 저장 위치 선택 */}
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>저장 위치</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
                  {storageOptions.map((option) => (
                    <div key={option.type} style={{ position: 'relative' }} ref={option.type === 'removable' ? dropdownRef : undefined}>
                      <button
                        type="button"
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
                          gap: '4px',
                          opacity: option.disabled ? 0.6 : 1,
                        }}
                      >
                        {option.icon}
                        <span>{option.label}</span>
                      </button>
                      {option.type === 'removable' && showDriveDropdown && (
                        <div style={{
                          position: 'absolute', top: '100%', left: '50%', transform: 'translateX(-50%)',
                          marginTop: '4px', backgroundColor: 'white', border: '1px solid #e5e7eb', borderRadius: '8px',
                          boxShadow: '0 4px 12px rgba(0,0,0,0.15)', zIndex: 100, minWidth: '140px', overflow: 'hidden',
                        }}>
                          <div style={{ padding: '8px 12px', backgroundColor: '#f9fafb', borderBottom: '1px solid #e5e7eb', fontSize: '11px', color: '#6b7280', fontWeight: '500' }}>
                            드라이브 선택
                          </div>
                          {removableDrives.length === 0 ? (
                            <div style={{ padding: '12px', fontSize: '12px', color: '#9ca3af', textAlign: 'center' }}>이동식 디스크 없음</div>
                          ) : (
                            removableDrives.map((drive) => (
                              <button
                                key={drive.letter}
                                type="button"
                                onClick={() => { setSelectedDrive(drive.letter); setShowDriveDropdown(false); }}
                                style={{
                                  width: '100%', padding: '10px 12px', border: 'none',
                                  backgroundColor: selectedDrive === drive.letter ? '#eff6ff' : 'white',
                                  color: selectedDrive === drive.letter ? '#2563eb' : '#374151',
                                  fontSize: '13px', fontWeight: selectedDrive === drive.letter ? '600' : '400',
                                  cursor: 'pointer', textAlign: 'left',
                                }}
                              >
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

              {/* 비밀번호 */}
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>인증서 비밀번호</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  minLength={8}
                  required
                />
                <p style={{ marginTop: '4px', fontSize: '12px', color: '#9ca3af' }}>8자 이상</p>
              </div>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '6px' }}>비밀번호 확인</label>
                <input
                  type="password"
                  value={passwordConfirm}
                  onChange={(e) => setPasswordConfirm(e.target.value)}
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  required
                />
              </div>
              <button type="submit" disabled={loading} style={{ width: '100%', padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', opacity: loading ? 0.5 : 1 }}>
                {loading ? '발급 중...' : '인증서 발급'}
              </button>
            </form>
          )}

          {/* Step 4: 발급 중 */}
          {step === 'issuing' && (
            <div style={{ textAlign: 'center', padding: '40px 0' }}>
              <div style={{ width: '48px', height: '48px', border: '3px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto 16px', animation: 'spin 1s linear infinite' }} />
              <p style={{ color: '#6b7280' }}>인증서 발급 및 저장 중...</p>
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
          )}

          {/* Step 5: 완료 */}
          {step === 'complete' && (
            <div style={{ textAlign: 'center', padding: '24px 0' }}>
              <div style={{ width: '64px', height: '64px', backgroundColor: '#dcfce7', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                <svg width="32" height="32" fill="none" stroke="#16a34a" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '8px' }}>인증서 발급 완료!</h3>
              <p style={{ color: '#6b7280', marginBottom: '24px', fontSize: '14px' }}>
                {storageType === 'harddisk' ? '하드디스크(C:)' : `이동식디스크(${selectedDrive}:)`}에 저장되었습니다.
              </p>
              <button onClick={handleClose} style={{ width: '100%', padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer' }}>
                확인
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
