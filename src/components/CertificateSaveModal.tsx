import { useState, useEffect } from 'react';

interface CertificateSaveModalProps {
  isOpen: boolean;
  onClose: () => void;
  certificateData: {
    p12Base64: string;
    serialNumber: string;
    subjectDN: string;
    notAfter: string;
  };
  onSaveComplete: () => void;
}

type SaveLocation = 'local' | 'usb' | 'download';

interface DriveInfo {
  letter: string;
  label: string;
  type: 'fixed' | 'removable';
  freeSpace?: string;
}

export default function CertificateSaveModal({
  isOpen,
  onClose,
  certificateData,
  onSaveComplete,
}: CertificateSaveModalProps) {
  const [step, setStep] = useState<'select' | 'password' | 'saving' | 'complete' | 'error'>('select');
  const [saveLocation, setSaveLocation] = useState<SaveLocation>('local');
  const [selectedDrive, setSelectedDrive] = useState<string>('C');
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [agentAvailable, setAgentAvailable] = useState(false);
  const [loading, setLoading] = useState(true);

  const agentUrl = process.env.NEXT_PUBLIC_AGENT_URL || 'http://localhost:52080';

  // Agent 상태 및 드라이브 목록 확인
  useEffect(() => {
    if (!isOpen) return;

    async function checkAgent() {
      setLoading(true);
      try {
        const healthRes = await fetch(`${agentUrl}/api/health`, {
          signal: AbortSignal.timeout(3000),
        });

        if (!healthRes.ok) throw new Error('Agent not available');
        setAgentAvailable(true);

        // 드라이브 목록 조회
        const drivesRes = await fetch(`${agentUrl}/api/drives`);
        if (drivesRes.ok) {
          const driveList = await drivesRes.json();
          setDrives(driveList);
        } else {
          // 기본 드라이브 설정
          setDrives([
            { letter: 'C', label: '로컬 디스크', type: 'fixed' },
          ]);
        }
      } catch {
        setAgentAvailable(false);
      } finally {
        setLoading(false);
      }
    }

    checkAgent();
  }, [isOpen, agentUrl]);

  async function handleSave() {
    setStep('saving');
    setError(null);

    try {
      if (saveLocation === 'download') {
        // 브라우저 다운로드
        downloadCertificate();
        setStep('complete');
        return;
      }

      // Agent를 통해 저장 (비밀번호 전달 안함!)
      const response = await fetch(`${agentUrl}/api/certificates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          p12Data: certificateData.p12Base64,  // P12 파일만 전달
          drive: selectedDrive,
          metadata: {
            serialNumber: certificateData.serialNumber,
            subjectDN: certificateData.subjectDN,
            notAfter: certificateData.notAfter,
          },
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error || '저장 실패');
      }

      setStep('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : '저장 중 오류 발생');
      setStep('error');
    }
  }

  function downloadCertificate() {
    const binaryString = atob(certificateData.p12Base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: 'application/x-pkcs12' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificate_${certificateData.serialNumber.substring(0, 8)}.p12`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function extractCN(dn: string): string {
    const match = dn.match(/CN=([^,]+)/);
    return match ? match[1] : dn;
  }

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full animate-slide-up">
        {/* 헤더 */}
        <div className="p-6 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-900">인증서 저장</h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <p className="mt-1 text-sm text-gray-500">
            발급된 인증서: {extractCN(certificateData.subjectDN)}
          </p>
        </div>

        <div className="p-6">
          {loading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-600 border-t-transparent mx-auto" />
              <p className="mt-4 text-gray-500">Agent 연결 확인 중...</p>
            </div>
          ) : step === 'select' ? (
            <>
              {/* 저장 위치 선택 */}
              <div className="space-y-3">
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  저장 위치 선택
                </label>

                {agentAvailable ? (
                  <>
                    {/* 로컬 디스크 */}
                    {drives.filter(d => d.type === 'fixed').map((drive) => (
                      <label
                        key={drive.letter}
                        className={`flex items-center p-4 border-2 rounded-xl cursor-pointer transition ${
                          saveLocation === 'local' && selectedDrive === drive.letter
                            ? 'border-blue-500 bg-blue-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        <input
                          type="radio"
                          name="saveLocation"
                          checked={saveLocation === 'local' && selectedDrive === drive.letter}
                          onChange={() => {
                            setSaveLocation('local');
                            setSelectedDrive(drive.letter);
                          }}
                          className="sr-only"
                        />
                        <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                          <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                          </svg>
                        </div>
                        <div className="flex-1">
                          <div className="font-medium text-gray-900">{drive.letter}: 드라이브 ({drive.label})</div>
                          <div className="text-sm text-gray-500">하드디스크에 저장</div>
                        </div>
                      </label>
                    ))}

                    {/* 이동식 디스크 */}
                    {drives.filter(d => d.type === 'removable').map((drive) => (
                      <label
                        key={drive.letter}
                        className={`flex items-center p-4 border-2 rounded-xl cursor-pointer transition ${
                          saveLocation === 'usb' && selectedDrive === drive.letter
                            ? 'border-green-500 bg-green-50'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        <input
                          type="radio"
                          name="saveLocation"
                          checked={saveLocation === 'usb' && selectedDrive === drive.letter}
                          onChange={() => {
                            setSaveLocation('usb');
                            setSelectedDrive(drive.letter);
                          }}
                          className="sr-only"
                        />
                        <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center mr-4">
                          <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                          </svg>
                        </div>
                        <div className="flex-1">
                          <div className="font-medium text-gray-900">{drive.letter}: 드라이브 ({drive.label})</div>
                          <div className="text-sm text-gray-500">이동식 디스크에 저장</div>
                        </div>
                      </label>
                    ))}
                  </>
                ) : (
                  <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-xl mb-3">
                    <p className="text-sm text-yellow-800">
                      Agent가 실행되지 않아 PC 저장이 불가능합니다.
                    </p>
                  </div>
                )}

                {/* 파일 다운로드 */}
                <label
                  className={`flex items-center p-4 border-2 rounded-xl cursor-pointer transition ${
                    saveLocation === 'download'
                      ? 'border-purple-500 bg-purple-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <input
                    type="radio"
                    name="saveLocation"
                    checked={saveLocation === 'download'}
                    onChange={() => setSaveLocation('download')}
                    className="sr-only"
                  />
                  <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center mr-4">
                    <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                  </div>
                  <div className="flex-1">
                    <div className="font-medium text-gray-900">파일로 다운로드</div>
                    <div className="text-sm text-gray-500">직접 파일을 저장하고 관리</div>
                  </div>
                </label>
              </div>

              <button
                onClick={() => setStep('password')}
                className="mt-6 w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700"
              >
                다음
              </button>
            </>
          ) : step === 'password' ? (
            <>
              {/* 비밀번호 설정 */}
              <div className="mb-4">
                <p className="text-sm text-gray-600 mb-4">
                  인증서 사용 시 필요한 비밀번호를 설정하세요.
                </p>

                {error && (
                  <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
                    {error}
                  </div>
                )}

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">비밀번호</label>
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="8자 이상 입력"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">비밀번호 확인</label>
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      placeholder="비밀번호 재입력"
                    />
                  </div>
                </div>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setStep('select')}
                  className="flex-1 border border-gray-300 py-3 rounded-lg font-medium hover:bg-gray-50"
                >
                  이전
                </button>
                <button
                  onClick={handleSave}
                  disabled={!password || !confirmPassword}
                  className="flex-1 bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 disabled:opacity-50"
                >
                  저장
                </button>
              </div>
            </>
          ) : step === 'saving' ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent mx-auto" />
              <p className="mt-4 text-gray-600">인증서 저장 중...</p>
            </div>
          ) : step === 'complete' ? (
            <div className="text-center py-8">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 className="text-lg font-bold text-gray-900 mb-2">저장 완료</h3>
              <p className="text-gray-500 text-sm mb-6">
                인증서가 성공적으로 저장되었습니다.
              </p>
              <button
                onClick={() => {
                  onSaveComplete();
                  onClose();
                }}
                className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700"
              >
                확인
              </button>
            </div>
          ) : step === 'error' ? (
            <div className="text-center py-8">
              <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h3 className="text-lg font-bold text-gray-900 mb-2">저장 실패</h3>
              <p className="text-red-600 text-sm mb-6">{error}</p>
              <button
                onClick={() => setStep('select')}
                className="w-full border border-gray-300 py-3 rounded-lg font-medium hover:bg-gray-50"
              >
                다시 시도
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
