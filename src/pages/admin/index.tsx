import { useState, useEffect } from 'react';
import Head from 'next/head';
import CertificateSelectModal from '@/components/CertificateSelectModal';

type Tab = 'dashboard' | 'clients' | 'certificates' | 'logs' | 'settings';

interface AdminUser {
  id: string;
  name: string;
  email: string;
}

export default function AdminPage() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [adminUser, setAdminUser] = useState<AdminUser | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [loading, setLoading] = useState(true);

  // 관리자 인증 상태
  const [showLogin, setShowLogin] = useState(true);
  const [showRegister, setShowRegister] = useState(false);

  useEffect(() => {
    const savedUser = sessionStorage.getItem('adminUser');
    if (savedUser) {
      const user = JSON.parse(savedUser);
      verifyAdmin(user.id);
    } else {
      setLoading(false);
    }
  }, []);

  async function verifyAdmin(userId: string) {
    try {
      const res = await fetch('/api/admin/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId }),
      });

      if (res.ok) {
        const data = await res.json();
        setAdminUser(data.user);
        setIsAuthenticated(true);
      } else {
        sessionStorage.removeItem('adminUser');
      }
    } catch {
      sessionStorage.removeItem('adminUser');
    } finally {
      setLoading(false);
    }
  }

  function handleLoginSuccess(user: AdminUser) {
    setAdminUser(user);
    setIsAuthenticated(true);
    sessionStorage.setItem('adminUser', JSON.stringify(user));
  }

  function handleLogout() {
    setIsAuthenticated(false);
    setAdminUser(null);
    sessionStorage.removeItem('adminUser');
  }

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: '48px', height: '48px', border: '4px solid #e5e7eb', borderTopColor: '#2563eb', borderRadius: '50%', margin: '0 auto', animation: 'spin 1s linear infinite' }} />
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <>
        <Head>
          <title>관리자 로그인 - 2Check PKI</title>
        </Head>
        <AdminLogin onSuccess={handleLoginSuccess} />
      </>
    );
  }

  return (
    <>
      <Head>
        <title>관리자 - 2Check PKI</title>
      </Head>
      <div style={{ minHeight: '100vh', backgroundColor: '#f3f4f6' }}>
        {/* Header */}
        <header style={{ backgroundColor: '#1f2937', color: 'white', padding: '16px 24px' }}>
          <div style={{ maxWidth: '1400px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ width: '36px', height: '36px', backgroundColor: '#3b82f6', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <svg width="20" height="20" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <span style={{ fontSize: '18px', fontWeight: 'bold' }}>2Check PKI Admin</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <span style={{ fontSize: '14px' }}>{adminUser?.name}</span>
              <button onClick={handleLogout} style={{ backgroundColor: '#374151', border: 'none', color: 'white', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontSize: '14px' }}>
                로그아웃
              </button>
            </div>
          </div>
        </header>

        <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '24px', display: 'flex', gap: '24px' }}>
          {/* Sidebar */}
          <nav style={{ width: '240px', flexShrink: 0 }}>
            <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
              {[
                { id: 'dashboard', label: '대시보드', icon: '📊' },
                { id: 'clients', label: 'OAuth 클라이언트', icon: '🔗' },
                { id: 'certificates', label: '인증서 관리', icon: '📜' },
                { id: 'logs', label: '감사 로그', icon: '📋' },
                { id: 'settings', label: '설정', icon: '⚙️' },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as Tab)}
                  style={{
                    width: '100%',
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    backgroundColor: activeTab === item.id ? '#eff6ff' : 'transparent',
                    color: activeTab === item.id ? '#2563eb' : '#374151',
                    border: 'none',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: activeTab === item.id ? '600' : '400',
                    textAlign: 'left',
                  }}
                >
                  <span>{item.icon}</span>
                  {item.label}
                </button>
              ))}
            </div>
          </nav>

          {/* Content */}
          <main style={{ flex: 1 }}>
            {activeTab === 'dashboard' && <Dashboard />}
            {activeTab === 'clients' && <ClientsPanel />}
            {activeTab === 'certificates' && <CertificatesPanel />}
            {activeTab === 'logs' && <LogsPanel />}
            {activeTab === 'settings' && <SettingsPanel />}
          </main>
        </div>
      </div>
    </>
  );
}

// 관리자 로그인 컴포넌트
function AdminLogin({ onSuccess }: { onSuccess: (user: AdminUser) => void }) {
  const [showCertModal, setShowCertModal] = useState(false);
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [step, setStep] = useState<'login' | 'register'>('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [adminSecret, setAdminSecret] = useState('');
  const [pendingSerialNumber, setPendingSerialNumber] = useState<string | null>(null);

  async function handleCertSelect(result: { userId?: string; user?: any }) {
    if (!result.userId) {
      setError('인증 정보를 가져올 수 없습니다.');
      return;
    }

    // 관리자 확인
    try {
      const adminRes = await fetch('/api/admin/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: result.userId }),
      });

      if (!adminRes.ok) {
        setError('관리자 권한이 없습니다.');
        return;
      }

      onSuccess(result.user);
    } catch {
      setError('관리자 확인 실패');
    }
  }

  // 관리자 등록용 인증서 선택 완료
  async function handleRegisterCertSelect(result: { serialNumber: string; user?: any }) {
    setPendingSerialNumber(result.serialNumber);
    setShowRegisterModal(false);
    setStep('register');
  }

  async function handleRegister() {
    if (!pendingSerialNumber || !adminSecret) {
      setError('인증서를 선택하고 관리자 시크릿을 입력하세요.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/admin/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serialNumber: pendingSerialNumber, adminSecret }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      alert(data.message);
      setPendingSerialNumber(null);
      setAdminSecret('');
      setStep('login');
    } catch (err) {
      setError(err instanceof Error ? err.message : '등록 실패');
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div style={{ minHeight: '100vh', backgroundColor: '#1f2937', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
        <div style={{ backgroundColor: 'white', borderRadius: '16px', padding: '32px', maxWidth: '450px', width: '100%' }}>
          <div style={{ textAlign: 'center', marginBottom: '24px' }}>
            <div style={{ width: '56px', height: '56px', backgroundColor: '#2563eb', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
              <svg width="28" height="28" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827' }}>관리자 로그인</h1>
            <p style={{ color: '#6b7280', fontSize: '14px', marginTop: '8px' }}>인증서로 로그인하세요</p>
          </div>

          {error && (
            <div style={{ padding: '12px', backgroundColor: '#fef2f2', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '16px', color: '#dc2626', fontSize: '14px' }}>
              {error}
            </div>
          )}

          {step === 'login' ? (
            <>
              <button
                onClick={() => setShowCertModal(true)}
                style={{ width: '100%', padding: '12px', backgroundColor: '#2563eb', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer' }}
              >
                인증서로 로그인
              </button>
              <div style={{ marginTop: '16px', textAlign: 'center' }}>
                <button 
                  onClick={() => setShowRegisterModal(true)} 
                  style={{ background: 'none', border: 'none', color: '#2563eb', fontSize: '14px', cursor: 'pointer' }}
                >
                  관리자 인증서 등록
                </button>
              </div>
            </>
          ) : (
            <>
              {/* 선택된 인증서 정보 표시 */}
              <div style={{ padding: '12px', backgroundColor: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', marginBottom: '16px' }}>
                <p style={{ fontSize: '14px', color: '#166534' }}>
                  선택된 인증서: <strong>{pendingSerialNumber?.substring(0, 16)}...</strong>
                </p>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px' }}>관리자 시크릿</label>
                <input 
                  type="password" 
                  value={adminSecret} 
                  onChange={(e) => setAdminSecret(e.target.value)} 
                  style={{ width: '100%', padding: '12px', border: '1px solid #d1d5db', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }} 
                  placeholder="ADMIN_SECRET" 
                />
                <p style={{ fontSize: '12px', color: '#6b7280', marginTop: '6px' }}>
                  .env 파일의 ADMIN_SECRET 값을 입력하세요.
                </p>
              </div>

              <button 
                onClick={handleRegister} 
                disabled={loading} 
                style={{ width: '100%', padding: '12px', backgroundColor: '#16a34a', color: 'white', border: 'none', borderRadius: '8px', fontSize: '14px', fontWeight: '500', cursor: 'pointer', opacity: loading ? 0.5 : 1 }}
              >
                {loading ? '등록 중...' : '관리자 등록'}
              </button>
              <div style={{ marginTop: '16px', textAlign: 'center' }}>
                <button 
                  onClick={() => { setStep('login'); setPendingSerialNumber(null); setAdminSecret(''); }} 
                  style={{ background: 'none', border: 'none', color: '#6b7280', fontSize: '14px', cursor: 'pointer' }}
                >
                  로그인으로 돌아가기
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* 로그인용 인증서 선택 모달 */}
      <CertificateSelectModal
        isOpen={showCertModal}
        onClose={() => setShowCertModal(false)}
        onSelect={handleCertSelect}
        title="관리자 인증서 선택"
        description="관리자 인증에 사용할 인증서를 선택하세요."
      />

      {/* 등록용 인증서 선택 모달 (서명 검증만 하고 결과 반환) */}
      <CertificateSelectModal
        isOpen={showRegisterModal}
        onClose={() => setShowRegisterModal(false)}
        onSelect={handleRegisterCertSelect}
        title="관리자로 등록할 인증서 선택"
        description="관리자로 등록할 인증서를 선택하세요."
      />
    </>
  );
}

// 대시보드 패널
function Dashboard() {
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    fetch('/api/admin/dashboard')
      .then((res) => res.json())
      .then(setData);
  }, []);

  if (!data) return <div>로딩 중...</div>;

  const statCards = [
    { label: '총 사용자', value: data.stats.users, color: '#3b82f6' },
    { label: '발급된 인증서', value: data.stats.certificates, color: '#10b981' },
    { label: '활성 인증서', value: data.stats.activeCertificates, color: '#8b5cf6' },
    { label: 'OAuth 클라이언트', value: data.stats.oauthClients, color: '#f59e0b' },
  ];

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '24px' }}>대시보드</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        {statCards.map((stat) => (
          <div key={stat.label} style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
            <p style={{ color: '#6b7280', fontSize: '14px', marginBottom: '8px' }}>{stat.label}</p>
            <p style={{ fontSize: '32px', fontWeight: 'bold', color: stat.color }}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px' }}>최근 발급된 인증서</h3>
          <table style={{ width: '100%', fontSize: '14px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
                <th style={{ padding: '8px 0', textAlign: 'left' }}>이름</th>
                <th style={{ padding: '8px 0', textAlign: 'left' }}>이메일</th>
                <th style={{ padding: '8px 0', textAlign: 'left' }}>발급일</th>
              </tr>
            </thead>
            <tbody>
              {data.recentCertificates.map((cert: any) => (
                <tr key={cert.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '8px 0' }}>{cert.user?.name}</td>
                  <td style={{ padding: '8px 0', color: '#6b7280' }}>{cert.user?.email}</td>
                  <td style={{ padding: '8px 0', color: '#6b7280' }}>{new Date(cert.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px' }}>최근 활동 로그</h3>
          <div style={{ maxHeight: '300px', overflow: 'auto' }}>
            {data.recentLogs.map((log: any) => (
              <div key={log.id} style={{ padding: '8px 0', borderBottom: '1px solid #f3f4f6', fontSize: '14px' }}>
                <span style={{ fontWeight: '500' }}>{log.action}</span>
                <span style={{ color: '#6b7280', marginLeft: '8px' }}>{new Date(log.createdAt).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// OAuth 클라이언트 패널
function ClientsPanel() {
  const [clients, setClients] = useState<any[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({ name: '', redirectUris: '' });
  const [newClient, setNewClient] = useState<{ clientId: string; clientSecret: string; name: string } | null>(null);

  useEffect(() => {
    loadClients();
  }, []);

  async function loadClients() {
    const res = await fetch('/api/admin/clients');
    setClients(await res.json());
  }

  async function handleCreate() {
    const res = await fetch('/api/admin/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: formData.name,
        redirectUris: formData.redirectUris.split('\n').filter(Boolean),
      }),
    });
    
    const data = await res.json();
    
    // 생성된 클라이언트 정보 표시 (secret 포함)
    setNewClient({
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      name: data.name,
    });
    
    setShowForm(false);
    setFormData({ name: '', redirectUris: '' });
    loadClients();
  }

  async function handleDelete(id: string) {
    if (!confirm('정말 삭제하시겠습니까?')) return;
    await fetch(`/api/admin/clients?id=${id}`, { method: 'DELETE' });
    loadClients();
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    alert('클립보드에 복사되었습니다.');
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold' }}>OAuth 클라이언트</h2>
        <button onClick={() => setShowForm(true)} style={{ backgroundColor: '#2563eb', color: 'white', padding: '10px 20px', border: 'none', borderRadius: '8px', cursor: 'pointer' }}>
          + 클라이언트 추가
        </button>
      </div>

      {/* 새로 생성된 클라이언트 정보 (Secret 표시) */}
      {newClient && (
        <div style={{ backgroundColor: '#f0fdf4', border: '2px solid #22c55e', padding: '24px', borderRadius: '12px', marginBottom: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold', color: '#166534', marginBottom: '8px' }}>
                ✅ 클라이언트가 생성되었습니다: {newClient.name}
              </h3>
              <p style={{ color: '#dc2626', fontSize: '14px', fontWeight: '500' }}>
                ⚠️ Client Secret은 지금만 확인 가능합니다. 반드시 안전한 곳에 저장하세요!
              </p>
            </div>
            <button 
              onClick={() => setNewClient(null)} 
              style={{ background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: '#6b7280' }}
            >
              ✕
            </button>
          </div>
          
          <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', marginBottom: '12px' }}>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>Client ID</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <code style={{ flex: 1, backgroundColor: '#f3f4f6', padding: '8px 12px', borderRadius: '6px', fontSize: '14px', fontFamily: 'monospace' }}>
                  {newClient.clientId}
                </code>
                <button 
                  onClick={() => copyToClipboard(newClient.clientId)}
                  style={{ padding: '8px 12px', backgroundColor: '#e5e7eb', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' }}
                >
                  복사
                </button>
              </div>
            </div>
            
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>Client Secret</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <code style={{ flex: 1, backgroundColor: '#fef2f2', padding: '8px 12px', borderRadius: '6px', fontSize: '14px', fontFamily: 'monospace', color: '#dc2626' }}>
                  {newClient.clientSecret}
                </code>
                <button 
                  onClick={() => copyToClipboard(newClient.clientSecret)}
                  style={{ padding: '8px 12px', backgroundColor: '#fee2e2', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', color: '#dc2626' }}
                >
                  복사
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showForm && (
        <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px', marginBottom: '24px' }}>
          <h3 style={{ marginBottom: '16px' }}>새 클라이언트</h3>
          <input
            placeholder="클라이언트 이름"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            style={{ width: '100%', padding: '10px', marginBottom: '12px', border: '1px solid #d1d5db', borderRadius: '6px', boxSizing: 'border-box' }}
          />
          <textarea
            placeholder="Redirect URIs (한 줄에 하나씩)"
            value={formData.redirectUris}
            onChange={(e) => setFormData({ ...formData, redirectUris: e.target.value })}
            style={{ width: '100%', padding: '10px', marginBottom: '12px', border: '1px solid #d1d5db', borderRadius: '6px', minHeight: '100px', boxSizing: 'border-box' }}
          />
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={handleCreate} style={{ backgroundColor: '#2563eb', color: 'white', padding: '10px 20px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>생성</button>
            <button onClick={() => setShowForm(false)} style={{ backgroundColor: '#e5e7eb', padding: '10px 20px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}>취소</button>
          </div>
        </div>
      )}

      <div style={{ backgroundColor: 'white', borderRadius: '12px', overflow: 'hidden' }}>
        <table style={{ width: '100%', fontSize: '14px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb' }}>
              <th style={{ padding: '12px', textAlign: 'left' }}>이름</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>Client ID</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>Redirect URIs</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>생성일</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>작업</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((client) => (
              <tr key={client.id} style={{ borderTop: '1px solid #e5e7eb' }}>
                <td style={{ padding: '12px', fontWeight: '500' }}>{client.name}</td>
                <td style={{ padding: '12px' }}>
                  <code style={{ backgroundColor: '#f3f4f6', padding: '2px 6px', borderRadius: '4px', fontSize: '12px' }}>
                    {client.clientId}
                  </code>
                </td>
                <td style={{ padding: '12px', color: '#6b7280', fontSize: '12px' }}>
                  {Array.isArray(client.redirectUris) ? client.redirectUris.join(', ') : '-'}
                </td>
                <td style={{ padding: '12px', color: '#6b7280' }}>{new Date(client.createdAt).toLocaleDateString()}</td>
                <td style={{ padding: '12px' }}>
                  <button onClick={() => handleDelete(client.id)} style={{ color: '#dc2626', background: 'none', border: 'none', cursor: 'pointer' }}>삭제</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: '24px', padding: '16px', backgroundColor: '#fffbeb', border: '1px solid #fcd34d', borderRadius: '8px' }}>
        <p style={{ fontSize: '14px', color: '#92400e' }}>
          💡 <strong>참고:</strong> Client Secret은 생성 시에만 확인할 수 있습니다. 
          분실한 경우 클라이언트를 삭제하고 새로 생성해야 합니다.
        </p>
      </div>
    </div>
  );
}

// 인증서 관리 패널
function CertificatesPanel() {
  const [data, setData] = useState<any>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    loadCertificates();
  }, [page]);

  async function loadCertificates() {
    const res = await fetch(`/api/admin/certificates?page=${page}`);
    setData(await res.json());
  }

  async function handleRevoke(id: string) {
    if (!confirm('이 인증서를 폐기하시겠습니까?')) return;
    await fetch('/api/admin/certificates', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, status: 'REVOKED' }),
    });
    loadCertificates();
  }

  if (!data) return <div>로딩 중...</div>;

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '24px' }}>인증서 관리</h2>

      <div style={{ backgroundColor: 'white', borderRadius: '12px', overflow: 'hidden' }}>
        <table style={{ width: '100%', fontSize: '14px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb' }}>
              <th style={{ padding: '12px', textAlign: 'left' }}>사용자</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>일련번호</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>상태</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>만료일</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>작업</th>
            </tr>
          </thead>
          <tbody>
            {data.certificates.map((cert: any) => (
              <tr key={cert.id} style={{ borderTop: '1px solid #e5e7eb' }}>
                <td style={{ padding: '12px' }}>{cert.user?.name}</td>
                <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '11px' }}>{cert.serialNumber.substring(0, 16)}...</td>
                <td style={{ padding: '12px' }}>
                  <span style={{ padding: '2px 8px', borderRadius: '9999px', fontSize: '12px', backgroundColor: cert.status === 'ACTIVE' ? '#dcfce7' : '#fef2f2', color: cert.status === 'ACTIVE' ? '#16a34a' : '#dc2626' }}>
                    {cert.status}
                  </span>
                </td>
                <td style={{ padding: '12px', color: '#6b7280' }}>{new Date(cert.notAfter).toLocaleDateString()}</td>
                <td style={{ padding: '12px' }}>
                  {cert.status === 'ACTIVE' && (
                    <button onClick={() => handleRevoke(cert.id)} style={{ color: '#dc2626', background: 'none', border: 'none', cursor: 'pointer' }}>폐기</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '16px' }}>
        <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>이전</button>
        <span style={{ padding: '8px 16px' }}>{page} / {data.pagination.totalPages}</span>
        <button onClick={() => setPage((p) => Math.min(data.pagination.totalPages, p + 1))} disabled={page === data.pagination.totalPages} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>다음</button>
      </div>
    </div>
  );
}

// 로그 패널
function LogsPanel() {
  const [data, setData] = useState<any>(null);
  const [page, setPage] = useState(1);

  useEffect(() => {
    fetch(`/api/admin/logs?page=${page}`)
      .then((res) => res.json())
      .then(setData);
  }, [page]);

  if (!data) return <div>로딩 중...</div>;

  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '24px' }}>감사 로그</h2>

      <div style={{ backgroundColor: 'white', borderRadius: '12px', overflow: 'hidden' }}>
        <table style={{ width: '100%', fontSize: '14px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb' }}>
              <th style={{ padding: '12px', textAlign: 'left' }}>시간</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>액션</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>사용자 ID</th>
              <th style={{ padding: '12px', textAlign: 'left' }}>IP</th>
            </tr>
          </thead>
          <tbody>
            {data.logs.map((log: any) => (
              <tr key={log.id} style={{ borderTop: '1px solid #e5e7eb' }}>
                <td style={{ padding: '12px', color: '#6b7280' }}>{new Date(log.createdAt).toLocaleString()}</td>
                <td style={{ padding: '12px', fontWeight: '500' }}>{log.action}</td>
                <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '11px' }}>{log.userId?.substring(0, 8) || '-'}</td>
                <td style={{ padding: '12px', color: '#6b7280' }}>{log.ipAddress || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '16px' }}>
        <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>이전</button>
        <span style={{ padding: '8px 16px' }}>{page} / {data.pagination.totalPages}</span>
        <button onClick={() => setPage((p) => Math.min(data.pagination.totalPages, p + 1))} disabled={page === data.pagination.totalPages} style={{ padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: '6px', cursor: 'pointer' }}>다음</button>
      </div>
    </div>
  );
}

// 설정 패널
function SettingsPanel() {
  return (
    <div>
      <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '24px' }}>설정</h2>
      <div style={{ backgroundColor: 'white', padding: '24px', borderRadius: '12px' }}>
        <p style={{ color: '#6b7280' }}>설정 기능은 추후 추가될 예정입니다.</p>
      </div>
    </div>
  );
}
