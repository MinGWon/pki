import { useState } from 'react';
import Head from "next/head";
import Link from "next/link";
import IssueCertificateModal from '@/components/IssueCertificateModal';
import LoginModal from '@/components/LoginModal';

export default function Home() {
  const [isIssueModalOpen, setIsIssueModalOpen] = useState(false);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  return (
    <>
      <Head>
        <title>2Check PKI - 인증서 기반 로그인 서비스</title>
        <meta name="description" content="PKI 기반 인증서 로그인 서비스" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      
      <div style={{ minHeight: '100vh', background: 'linear-gradient(to bottom, #f8fafc, #ffffff, #eff6ff)' }}>
        {/* Header */}
        <header style={{ 
          padding: '16px 24px', 
          borderBottom: '1px solid #e5e7eb', 
          backgroundColor: 'rgba(255,255,255,0.9)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          backdropFilter: 'blur(8px)'
        }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            {/* ...existing code for logo... */}
            <Link href="/" style={{ display: 'flex', alignItems: 'center', gap: '8px', textDecoration: 'none' }}>
              <div style={{ 
                width: '36px', 
                height: '36px', 
                background: 'linear-gradient(135deg, #2563eb, #4f46e5)', 
                borderRadius: '8px', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center' 
              }}>
                <svg width="20" height="20" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827' }}>2Check PKI</span>
            </Link>
            
            <nav style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
              <button 
                onClick={() => setIsIssueModalOpen(true)}
                style={{ color: '#4b5563', fontSize: '14px', fontWeight: '500', background: 'none', border: 'none', cursor: 'pointer' }}
              >
                인증서 발급
              </button>
              <Link href="/download/agent" style={{ color: '#4b5563', fontSize: '14px', fontWeight: '500', textDecoration: 'none' }}>
                Agent 다운로드
              </Link>
              <Link href="/docs" style={{ color: '#4b5563', fontSize: '14px', fontWeight: '500', textDecoration: 'none' }}>
                개발자 문서
              </Link>
              <button 
                onClick={() => setIsLoginModalOpen(true)}
                style={{ 
                  backgroundColor: '#2563eb', 
                  color: 'white', 
                  padding: '8px 16px', 
                  borderRadius: '8px', 
                  fontSize: '14px', 
                  fontWeight: '500',
                  border: 'none',
                  cursor: 'pointer',
                }}
              >
                로그인
              </button>
            </nav>
          </div>
        </header>

        {/* Hero */}
        <main style={{ maxWidth: '1200px', margin: '0 auto', padding: '80px 24px 128px' }}>
          <div style={{ textAlign: 'center', maxWidth: '768px', margin: '0 auto' }}>
            {/* ...existing code for badge and title... */}
            <div style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '8px', 
              backgroundColor: '#eff6ff', 
              color: '#1d4ed8', 
              padding: '8px 16px', 
              borderRadius: '9999px', 
              fontSize: '14px', 
              fontWeight: '500', 
              marginBottom: '24px' 
            }}>
              <span style={{ width: '8px', height: '8px', backgroundColor: '#3b82f6', borderRadius: '50%' }}></span>
              PKI 기반 인증 시스템
            </div>
            
            <h1 style={{ fontSize: '48px', fontWeight: 'bold', color: '#111827', lineHeight: '1.2', marginBottom: '24px' }}>
              비밀번호 없이,<br />
              <span style={{ background: 'linear-gradient(90deg, #2563eb, #4f46e5)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                인증서로 안전하게
              </span>
            </h1>
            
            <p style={{ fontSize: '20px', color: '#6b7280', marginBottom: '40px' }}>
              2Check PKI로 비밀번호 유출 걱정 없이 안전하게 로그인하세요.
            </p>
            
            <div style={{ display: 'flex', justifyContent: 'center', gap: '16px' }}>
              <button 
                onClick={() => setIsIssueModalOpen(true)}
                style={{ 
                  backgroundColor: '#2563eb', 
                  color: 'white', 
                  padding: '12px 32px', 
                  borderRadius: '8px', 
                  fontWeight: '500',
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: '0 4px 14px rgba(37, 99, 235, 0.25)'
                }}
              >
                인증서 발급받기
              </button>
              <button 
                onClick={() => setIsLoginModalOpen(true)}
                style={{ 
                  backgroundColor: '#16a34a', 
                  color: 'white', 
                  padding: '12px 32px', 
                  borderRadius: '8px', 
                  fontWeight: '500',
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: '0 4px 14px rgba(22, 163, 74, 0.25)'
                }}
              >
                로그인
              </button>
              <Link href="/docs" style={{ 
                border: '1px solid #d1d5db', 
                color: '#374151', 
                padding: '12px 32px', 
                borderRadius: '8px', 
                fontWeight: '500', 
                textDecoration: 'none',
                backgroundColor: 'white'
              }}>
                개발자 문서
              </Link>
            </div>
          </div>

          {/* Features */}
          <div style={{ marginTop: '128px', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '32px' }}>
            {/* 강력한 보안 */}
            <div style={{ 
              backgroundColor: 'white', 
              padding: '32px', 
              borderRadius: '16px', 
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)', 
              border: '1px solid #f3f4f6' 
            }}>
              <div style={{ 
                width: '56px', 
                height: '56px', 
                background: 'linear-gradient(135deg, #3b82f6, #2563eb)', 
                borderRadius: '16px', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                marginBottom: '24px',
                boxShadow: '0 4px 14px rgba(59, 130, 246, 0.3)'
              }}>
                <svg width="28" height="28" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827', marginBottom: '12px' }}>강력한 보안</h3>
              <p style={{ color: '#6b7280', lineHeight: '1.6' }}>
                PKI 기반 공개키 암호화로 비밀번호 유출 걱정 없이 안전하게 인증합니다.
              </p>
            </div>

            {/* 빠른 연동 */}
            <div style={{ 
              backgroundColor: 'white', 
              padding: '32px', 
              borderRadius: '16px', 
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)', 
              border: '1px solid #f3f4f6' 
            }}>
              <div style={{ 
                width: '56px', 
                height: '56px', 
                background: 'linear-gradient(135deg, #22c55e, #16a34a)', 
                borderRadius: '16px', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                marginBottom: '24px',
                boxShadow: '0 4px 14px rgba(34, 197, 94, 0.3)'
              }}>
                <svg width="28" height="28" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827', marginBottom: '12px' }}>빠른 연동</h3>
              <p style={{ color: '#6b7280', lineHeight: '1.6' }}>
                OAuth2 표준을 지원하여 기존 서비스에 쉽게 연동할 수 있습니다.
              </p>
            </div>

            {/* 법적 효력 */}
            <div style={{ 
              backgroundColor: 'white', 
              padding: '32px', 
              borderRadius: '16px', 
              boxShadow: '0 1px 3px rgba(0,0,0,0.1)', 
              border: '1px solid #f3f4f6' 
            }}>
              <div style={{ 
                width: '56px', 
                height: '56px', 
                background: 'linear-gradient(135deg, #a855f7, #7c3aed)', 
                borderRadius: '16px', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                marginBottom: '24px',
                boxShadow: '0 4px 14px rgba(168, 85, 247, 0.3)'
              }}>
                <svg width="28" height="28" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#111827', marginBottom: '12px' }}>법적 효력</h3>
              <p style={{ color: '#6b7280', lineHeight: '1.6' }}>
                전자서명법에 따른 공인인증서와 동등한 법적 효력을 가집니다.
              </p>
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer style={{ borderTop: '1px solid #e5e7eb', padding: '32px 24px', backgroundColor: '#f9fafb' }}>
          <div style={{ maxWidth: '1200px', margin: '0 auto', textAlign: 'center', fontSize: '14px', color: '#6b7280' }}>
            © 2024 2Check PKI. All rights reserved.
          </div>
        </footer>
      </div>

      {/* 모달 */}
      <IssueCertificateModal 
        isOpen={isIssueModalOpen} 
        onClose={() => setIsIssueModalOpen(false)} 
      />
      <LoginModal 
        isOpen={isLoginModalOpen} 
        onClose={() => setIsLoginModalOpen(false)} 
      />
    </>
  );
}
