import { useState, useRef } from 'react';
import { parsePKCS12, ParsedPKCS12, validatePKCS12Password } from '@/lib/pkcs12-parser';

interface CertificateImportProps {
  onImport: (parsed: ParsedPKCS12, file: File) => void;
  onCancel?: () => void;
}

export default function CertificateImport({ onImport, onCancel }: CertificateImportProps) {
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<ParsedPKCS12 | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setError(null);
      setPreview(null);
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && (droppedFile.name.endsWith('.p12') || droppedFile.name.endsWith('.pfx'))) {
      setFile(droppedFile);
      setError(null);
      setPreview(null);
    } else {
      setError('P12 또는 PFX 파일만 지원합니다.');
    }
  }

  async function handlePasswordSubmit() {
    if (!file || !password) {
      setError('파일과 비밀번호를 입력해주세요.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const buffer = await file.arrayBuffer();
      
      if (!validatePKCS12Password(buffer, password)) {
        setError('비밀번호가 올바르지 않습니다.');
        setLoading(false);
        return;
      }

      const parsed = parsePKCS12(buffer, password);
      setPreview(parsed);
    } catch (err) {
      setError(err instanceof Error ? err.message : '인증서 파싱 실패');
    } finally {
      setLoading(false);
    }
  }

  function handleImport() {
    if (preview && file) {
      onImport(preview, file);
    }
  }

  function formatDate(date: Date): string {
    return new Date(date).toLocaleDateString('ko-KR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }

  function extractCN(dn: string): string {
    const match = dn.match(/CN=([^,]+)/);
    return match ? match[1] : dn;
  }

  function getDaysRemaining(date: Date): number {
    const diff = new Date(date).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  }

  return (
    <div className="card p-8 max-w-md w-full animate-slide-up">
      {/* 헤더 */}
      <div className="text-center mb-6">
        <div className="w-14 h-14 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center mx-auto mb-4 shadow-lg">
          <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
        </div>
        <h2 className="text-xl font-bold text-gray-900">인증서 가져오기</h2>
        <p className="mt-1 text-gray-500 text-sm">PKCS#12 파일(.p12, .pfx)을 선택하세요</p>
      </div>

      {error && (
        <div className="alert-error mb-6 flex items-center">
          <svg className="w-5 h-5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
          {error}
        </div>
      )}

      {!preview ? (
        <>
          {/* 파일 드롭존 */}
          <div className="mb-5">
            <div
              onClick={() => fileInputRef.current?.click()}
              onDrop={handleDrop}
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 ${
                isDragging 
                  ? 'border-blue-500 bg-blue-50' 
                  : file 
                    ? 'border-green-500 bg-green-50' 
                    : 'border-gray-300 hover:border-gray-400 hover:bg-gray-50'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".p12,.pfx"
                onChange={handleFileChange}
                className="hidden"
              />
              {file ? (
                <div>
                  <div className="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center mx-auto mb-3">
                    <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="font-medium text-gray-900">{file.name}</p>
                  <p className="text-sm text-gray-500 mt-1">{(file.size / 1024).toFixed(1)} KB</p>
                  <button 
                    onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    className="mt-3 text-sm text-red-600 hover:text-red-700"
                  >
                    파일 제거
                  </button>
                </div>
              ) : (
                <div>
                  <div className="w-12 h-12 bg-gray-100 rounded-xl flex items-center justify-center mx-auto mb-3">
                    <svg className="w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <p className="font-medium text-gray-700">클릭하거나 파일을 드래그하세요</p>
                  <p className="text-sm text-gray-400 mt-1">.p12, .pfx 파일</p>
                </div>
              )}
            </div>
          </div>

          {/* 비밀번호 */}
          <div className="mb-6">
            <label className="label">인증서 비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handlePasswordSubmit()}
              className="input"
              placeholder="비밀번호 입력"
            />
          </div>

          {/* 버튼 */}
          <div className="flex gap-3">
            {onCancel && (
              <button onClick={onCancel} className="btn-secondary flex-1">
                취소
              </button>
            )}
            <button
              onClick={handlePasswordSubmit}
              disabled={!file || !password || loading}
              className="btn-primary flex-1"
            >
              {loading ? (
                <>
                  <div className="spinner w-4 h-4 mr-2 border-2" />
                  확인 중...
                </>
              ) : (
                '확인'
              )}
            </button>
          </div>
        </>
      ) : (
        <>
          {/* 인증서 미리보기 */}
          <div className="mb-6">
            <div className="bg-gray-50 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <span className="font-semibold text-gray-900">인증서 정보</span>
                {preview.certificate.isExpired ? (
                  <span className="badge-error">만료됨</span>
                ) : getDaysRemaining(preview.certificate.notAfter) <= 30 ? (
                  <span className="badge-warning">{getDaysRemaining(preview.certificate.notAfter)}일 후 만료</span>
                ) : (
                  <span className="badge-success">유효</span>
                )}
              </div>
              
              <dl className="space-y-3 text-sm">
                <div className="flex">
                  <dt className="w-20 flex-shrink-0 text-gray-500">소유자</dt>
                  <dd className="font-medium text-gray-900">{extractCN(preview.certificate.subjectDN)}</dd>
                </div>
                <div className="flex">
                  <dt className="w-20 flex-shrink-0 text-gray-500">발급자</dt>
                  <dd className="text-gray-700">{extractCN(preview.certificate.issuerDN)}</dd>
                </div>
                <div className="flex">
                  <dt className="w-20 flex-shrink-0 text-gray-500">일련번호</dt>
                  <dd className="font-mono text-xs text-gray-600 truncate">{preview.certificate.serialNumber}</dd>
                </div>
                <div className="flex">
                  <dt className="w-20 flex-shrink-0 text-gray-500">유효기간</dt>
                  <dd className="text-gray-700">
                    {formatDate(preview.certificate.notBefore)} ~ {formatDate(preview.certificate.notAfter)}
                  </dd>
                </div>
              </dl>

              {preview.chainCertificates.length > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <p className="text-xs text-gray-500 flex items-center">
                    <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                    체인 인증서 {preview.chainCertificates.length}개 포함
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* 버튼 */}
          <div className="flex gap-3">
            <button
              onClick={() => {
                setPreview(null);
                setPassword('');
              }}
              className="btn-secondary flex-1"
            >
              다시 선택
            </button>
            <button
              onClick={handleImport}
              disabled={preview.certificate.isExpired}
              className="btn-primary flex-1"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              가져오기
            </button>
          </div>

          {preview.certificate.isExpired && (
            <p className="mt-4 text-sm text-center text-red-600">
              만료된 인증서는 가져올 수 없습니다.
            </p>
          )}
        </>
      )}
    </div>
  );
}
