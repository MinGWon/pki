import { useState, useCallback } from 'react';
import { parsePKCS12, ParsedPKCS12, signWithPrivateKey } from '@/lib/pkcs12-parser';
import { arrayBufferToBase64 } from '@/lib/browser-crypto';

interface StoredCertificate {
  id: string;
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore: string;
  notAfter: string;
  isExpired: boolean;
  p12Base64: string; // 암호화된 P12 저장
}

const STORAGE_KEY = '2check_certificates';

export function useCertificate() {
  const [certificates, setCertificates] = useState<StoredCertificate[]>([]);
  const [loading, setLoading] = useState(false);

  // IndexedDB에서 인증서 목록 로드
  const loadCertificates = useCallback(async () => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const certs: StoredCertificate[] = JSON.parse(stored);
        // 만료 상태 업데이트
        const now = new Date();
        const updated = certs.map((c) => ({
          ...c,
          isExpired: new Date(c.notAfter) < now,
        }));
        setCertificates(updated);
      }
    } catch (error) {
      console.error('Failed to load certificates:', error);
    }
  }, []);

  // 인증서 저장
  const saveCertificate = useCallback(async (
    parsed: ParsedPKCS12,
    p12Buffer: ArrayBuffer
  ): Promise<string> => {
    const id = crypto.randomUUID();
    const newCert: StoredCertificate = {
      id,
      serialNumber: parsed.certificate.serialNumber,
      subjectDN: parsed.certificate.subjectDN,
      issuerDN: parsed.certificate.issuerDN,
      notBefore: parsed.certificate.notBefore.toISOString(),
      notAfter: parsed.certificate.notAfter.toISOString(),
      isExpired: parsed.certificate.isExpired,
      p12Base64: arrayBufferToBase64(p12Buffer),
    };

    const stored = localStorage.getItem(STORAGE_KEY);
    const certs: StoredCertificate[] = stored ? JSON.parse(stored) : [];
    
    // 중복 체크
    const exists = certs.some((c) => c.serialNumber === newCert.serialNumber);
    if (exists) {
      throw new Error('이미 등록된 인증서입니다.');
    }

    certs.push(newCert);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(certs));
    setCertificates(certs);

    return id;
  }, []);

  // 인증서 삭제
  const deleteCertificate = useCallback(async (id: string) => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return;

    const certs: StoredCertificate[] = JSON.parse(stored);
    const filtered = certs.filter((c) => c.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
    setCertificates(filtered);
  }, []);

  // 서명 생성
  const sign = useCallback(async (
    certId: string,
    data: string,
    password: string
  ): Promise<{ signature: string; serialNumber: string }> => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) throw new Error('No certificates stored');

    const certs: StoredCertificate[] = JSON.parse(stored);
    const cert = certs.find((c) => c.id === certId);
    if (!cert) throw new Error('Certificate not found');

    // P12 복원 및 파싱
    const p12Binary = atob(cert.p12Base64);
    const p12Buffer = new Uint8Array(p12Binary.length);
    for (let i = 0; i < p12Binary.length; i++) {
      p12Buffer[i] = p12Binary.charCodeAt(i);
    }

    const parsed = parsePKCS12(p12Buffer.buffer, password);
    const signature = signWithPrivateKey(parsed.privateKeyPem, data);

    return {
      signature,
      serialNumber: parsed.certificate.serialNumber,
    };
  }, []);

  return {
    certificates,
    loading,
    loadCertificates,
    saveCertificate,
    deleteCertificate,
    sign,
  };
}
