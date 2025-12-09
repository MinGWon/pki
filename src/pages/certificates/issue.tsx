import { useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import CertificateSaveModal from '@/components/CertificateSaveModal';

type Step = 'form' | 'verify' | 'password' | 'issuing' | 'save' | 'complete';

export default function IssueCertificatePage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>('form');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formData, setFormData] = useState({ name: '', email: '', phone: '' });
  const [verificationCode, setVerificationCode] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');

  const [userId, setUserId] = useState<string | null>(null);
  const [certData, setCertData] = useState<{
    p12Base64: string;
    serialNumber: string;
    subjectDN: string;
    notAfter: string;
  } | null>(null);

  async function handleFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // 사용자 등록 (전화번호 기반 userId 생성은 서버에서 처리)
      const res = await fetch('/api/users/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || '등록 실패');
      }

      setUserId(data.user.id);
      // TODO: 실제로는 이메일/SMS 인증 구현
      setStep('verify');
    } catch (err) {
      setError(err instanceof Error ? err.message : '오류 발생');
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    // TODO: 실제 인증 코드 검증 구현
    // 현재는 임시로 바로 통과
    if (verificationCode.length >= 4) {
      setStep('password');
    } else {
      setError('인증 코드를 입력해주세요.');
    }
  }

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('비밀번호는 8자 이상이어야 합니다.');
      return;
    }

    if (password !== passwordConfirm) {
      setError('비밀번호가 일치하지 않습니다.');
      return;
    }

    setStep('issuing');
    setLoading(true);

    try {
      const res = await fetch('/api/certificates/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          commonName: formData.name,
          email: formData.email,
          password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || '인증서 발급 실패');
      }

      setCertData({
        p12Base64: data.p12,
        serialNumber: data.certificate.serialNumber,
        subjectDN: data.certificate.subjectDN,
        notAfter: data.certificate.notAfter,
      });

      setStep('save');
    } catch (err) {
      setError(err instanceof Error ? err.message : '오류 발생');
      setStep('password');
    } finally {
      setLoading(false);
    }
  }

  function handleSaveComplete() {
    setStep('complete');
  }

  return (
    <>
      <Head>
        <title>인증서 발급 - 2Check PKI</title>
      </Head>
      <div className="min-h-screen bg-gray-50 py-12 px-4">
        <div className="max-w-lg mx-auto">
          {/* Progress */}
          <div className="mb-8">
            <div className="flex items-center justify-between">
              {['정보입력', '본인인증', '비밀번호', '발급', '저장'].map((label, idx) => {
                const steps: Step[] = ['form', 'verify', 'password', 'issuing', 'save'];
                const currentIdx = steps.indexOf(step);
                const isActive = currentIdx >= idx || step === 'complete';
                return (
                  <div key={label} className="flex items-center">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                      isActive ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
                    }`}>
                      {idx + 1}
                    </div>
                    {idx < 4 && <div className="w-6 h-0.5 bg-gray-200 mx-1" />}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-lg p-8">
            {error && (
              <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
                {error}
              </div>
            )}

            {/* Step 1: 정보 입력 */}
            {step === 'form' && (
              <form onSubmit={handleFormSubmit}>
                <h2 className="text-xl font-bold mb-6">정보 입력</h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">이름</label>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full border rounded-lg px-4 py-2"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">이메일</label>
                    <input
                      type="email"
                      value={formData.email}
                      onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                      className="w-full border rounded-lg px-4 py-2"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">휴대폰</label>
                    <input
                      type="tel"
                      value={formData.phone}
                      onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                      className="w-full border rounded-lg px-4 py-2"
                      placeholder="010-0000-0000"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="mt-6 w-full bg-blue-600 text-white py-3 rounded-lg disabled:opacity-50"
                >
                  {loading ? '처리 중...' : '다음'}
                </button>
              </form>
            )}

            {/* Step 2: 본인 인증 */}
            {step === 'verify' && (
              <form onSubmit={handleVerify}>
                <h2 className="text-xl font-bold mb-6">본인 인증</h2>
                <p className="text-gray-600 mb-4">
                  {formData.email}로 인증 코드가 발송되었습니다.
                </p>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">인증 코드</label>
                  <input
                    type="text"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    className="w-full border rounded-lg px-4 py-2 text-center text-2xl tracking-widest"
                    maxLength={6}
                    placeholder="000000"
                  />
                </div>
                <p className="mt-2 text-sm text-gray-500">
                  (테스트: 아무 4자리 이상 입력)
                </p>
                <button
                  type="submit"
                  className="mt-6 w-full bg-blue-600 text-white py-3 rounded-lg"
                >
                  확인
                </button>
              </form>
            )}

            {/* Step 3: 비밀번호 설정 */}
            {step === 'password' && (
              <form onSubmit={handlePasswordSubmit}>
                <h2 className="text-xl font-bold mb-6">인증서 비밀번호 설정</h2>
                <p className="text-gray-600 mb-4">
                  인증서 사용 시 필요한 비밀번호를 설정하세요.
                </p>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">비밀번호</label>
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full border rounded-lg px-4 py-2"
                      minLength={8}
                      required
                    />
                    <p className="mt-1 text-xs text-gray-500">8자 이상</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">비밀번호 확인</label>
                    <input
                      type="password"
                      value={passwordConfirm}
                      onChange={(e) => setPasswordConfirm(e.target.value)}
                      className="w-full border rounded-lg px-4 py-2"
                      required
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="mt-6 w-full bg-blue-600 text-white py-3 rounded-lg disabled:opacity-50"
                >
                  {loading ? '인증서 발급 중...' : '인증서 발급'}
                </button>
              </form>
            )}

            {/* Step 4: 발급 중 */}
            {step === 'issuing' && (
              <div className="text-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent mx-auto" />
                <p className="mt-4 text-gray-600">인증서 발급 중...</p>
              </div>
            )}

            {/* Step 5: 완료 */}
            {step === 'complete' && (
              <div className="text-center py-8">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h2 className="text-xl font-bold mb-2">인증서 발급 및 저장 완료</h2>
                <p className="text-gray-600 mb-6">이제 인증서 로그인을 사용할 수 있습니다.</p>
                <button onClick={() => router.push('/auth/certificate')} className="w-full bg-blue-600 text-white py-3 rounded-lg">
                  로그인하러 가기
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 저장 모달 */}
      {certData && (
        <CertificateSaveModal
          isOpen={step === 'save'}
          onClose={() => setStep('complete')}
          certificateData={certData}
          onSaveComplete={handleSaveComplete}
        />
      )}
    </>
  );
}
