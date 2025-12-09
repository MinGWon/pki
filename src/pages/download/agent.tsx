import Head from 'next/head';
import Link from 'next/link';

export default function AgentDownloadPage() {
  return (
    <>
      <Head>
        <title>Agent 다운로드 - 2Check PKI</title>
      </Head>
      <div className="min-h-screen bg-gray-50 py-12 px-4">
        <div className="max-w-2xl mx-auto">
          <div className="bg-white rounded-xl shadow-lg p-8">
            <h1 className="text-2xl font-bold text-center mb-2">2Check Agent 다운로드</h1>
            <p className="text-center text-gray-600 mb-8">
              인증서 로그인을 위해 Agent 설치가 필요합니다.
            </p>

            {/* 다운로드 버튼 */}
            <div className="space-y-4 mb-8">
              <a
                href="/downloads/2CheckAgent-Setup.exe"
                className="flex items-center justify-between p-4 border-2 border-blue-600 rounded-lg hover:bg-blue-50 transition"
              >
                <div className="flex items-center">
                  <svg className="w-10 h-10 text-blue-600 mr-4" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
                  </svg>
                  <div>
                    <div className="font-semibold">Windows 64-bit</div>
                    <div className="text-sm text-gray-500">Windows 10/11</div>
                  </div>
                </div>
                <span className="text-blue-600 font-medium">다운로드</span>
              </a>

              <div className="flex items-center justify-between p-4 border rounded-lg bg-gray-50 opacity-60">
                <div className="flex items-center">
                  <svg className="w-10 h-10 text-gray-400 mr-4" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 18c-4.418 0-8-3.582-8-8s3.582-8 8-8 8 3.582 8 8-3.582 8-8 8z"/>
                  </svg>
                  <div>
                    <div className="font-semibold text-gray-500">macOS</div>
                    <div className="text-sm text-gray-400">준비 중</div>
                  </div>
                </div>
                <span className="text-gray-400">Coming Soon</span>
              </div>
            </div>

            {/* 설치 가이드 */}
            <div className="border-t pt-6">
              <h2 className="font-semibold mb-4">설치 방법</h2>
              <ol className="space-y-3 text-sm text-gray-600">
                <li className="flex">
                  <span className="w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mr-3 flex-shrink-0">1</span>
                  <span>위 다운로드 버튼을 클릭하여 설치 파일을 다운로드합니다.</span>
                </li>
                <li className="flex">
                  <span className="w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mr-3 flex-shrink-0">2</span>
                  <span>다운로드한 <code className="bg-gray-100 px-1 rounded">2CheckAgent-Setup.exe</code> 파일을 실행합니다.</span>
                </li>
                <li className="flex">
                  <span className="w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mr-3 flex-shrink-0">3</span>
                  <span>설치 마법사의 안내에 따라 설치를 완료합니다.</span>
                </li>
                <li className="flex">
                  <span className="w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center mr-3 flex-shrink-0">4</span>
                  <span>시스템 트레이에서 2Check Agent 아이콘을 확인합니다.</span>
                </li>
              </ol>
            </div>

            {/* 인증서 등록 안내 */}
            <div className="mt-6 p-4 bg-yellow-50 rounded-lg">
              <h3 className="font-medium text-yellow-800 mb-2">인증서 등록</h3>
              <p className="text-sm text-yellow-700">
                Agent 설치 후, 발급받은 인증서(.p12 파일)를 Agent에 등록해야 합니다.
                시스템 트레이의 Agent 아이콘을 우클릭하여 &quot;인증서 등록&quot;을 선택하세요.
              </p>
            </div>

            <div className="mt-6 text-center">
              <Link href="/" className="text-blue-600 hover:underline text-sm">
                ← 홈으로 돌아가기
              </Link>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
