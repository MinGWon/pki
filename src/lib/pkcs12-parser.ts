/**
 * PKCS#12 파일 파싱 유틸리티
 * node-forge를 브라우저에서 사용
 */

import forge from 'node-forge';

export interface ParsedCertificate {
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyPem: string;
  isExpired: boolean;
  isCA: boolean;
}

export interface ParsedPKCS12 {
  certificate: ParsedCertificate;
  privateKeyPem: string;
  chainCertificates: ParsedCertificate[];
}

// DN 속성을 문자열로 변환
function attributesToDN(attributes: forge.pki.CertificateField[]): string {
  return attributes
    .map((attr) => `${attr.shortName}=${attr.value}`)
    .join(', ');
}

// 인증서 파싱
function parseCertificate(cert: forge.pki.Certificate): ParsedCertificate {
  const now = new Date();
  
  // Basic Constraints 확인
  const basicConstraints = cert.getExtension('basicConstraints');
  const isCA = basicConstraints ? (basicConstraints as any).cA === true : false;
  
  return {
    serialNumber: cert.serialNumber,
    subjectDN: attributesToDN(cert.subject.attributes),
    issuerDN: attributesToDN(cert.issuer.attributes),
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
    publicKeyPem: forge.pki.publicKeyToPem(cert.publicKey),
    isExpired: now > cert.validity.notAfter,
    isCA,
  };
}

// PKCS#12 파일 파싱
export function parsePKCS12(
  p12Buffer: ArrayBuffer,
  password: string
): ParsedPKCS12 {
  // ArrayBuffer를 forge 형식으로 변환
  const p12Der = forge.util.createBuffer(new Uint8Array(p12Buffer));
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  
  // PKCS#12 디코딩
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  
  // 인증서와 개인키 추출
  const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  
  const certBags = bags[forge.pki.oids.certBag] || [];
  const privateKeyBags = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  
  if (certBags.length === 0) {
    throw new Error('No certificate found in PKCS#12 file');
  }
  
  if (privateKeyBags.length === 0) {
    throw new Error('No private key found in PKCS#12 file');
  }
  
  // 개인키
  const privateKey = privateKeyBags[0].key;
  if (!privateKey) {
    throw new Error('Failed to extract private key');
  }
  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
  
  // 인증서 분류 (엔드 엔티티 vs 체인)
  const parsedCerts = certBags
    .filter((bag) => bag.cert)
    .map((bag) => parseCertificate(bag.cert!));
  
  // 엔드 엔티티 인증서 찾기 (CA가 아닌 것)
  const endEntityCert = parsedCerts.find((c) => !c.isCA);
  const chainCerts = parsedCerts.filter((c) => c.isCA);
  
  if (!endEntityCert) {
    // CA가 아닌 인증서가 없으면 첫 번째 인증서 사용
    return {
      certificate: parsedCerts[0],
      privateKeyPem,
      chainCertificates: parsedCerts.slice(1),
    };
  }
  
  return {
    certificate: endEntityCert,
    privateKeyPem,
    chainCertificates: chainCerts,
  };
}

// PKCS#12 파일 유효성 검사 (비밀번호 확인용)
export function validatePKCS12Password(
  p12Buffer: ArrayBuffer,
  password: string
): boolean {
  try {
    parsePKCS12(p12Buffer, password);
    return true;
  } catch {
    return false;
  }
}

// X.509 PEM 인증서 파싱
export function parseX509PEM(pem: string): ParsedCertificate {
  const cert = forge.pki.certificateFromPem(pem);
  return parseCertificate(cert);
}

// 개인키로 서명 생성 (forge 사용)
export function signWithPrivateKey(
  privateKeyPem: string,
  data: string
): string {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const md = forge.md.sha256.create();
  md.update(data, 'utf8');
  
  const signature = privateKey.sign(md);
  return forge.util.encode64(signature);
}

// 공개키로 서명 검증
export function verifyWithPublicKey(
  publicKeyPem: string,
  data: string,
  signature: string
): boolean {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(data, 'utf8');
    
    const signatureBytes = forge.util.decode64(signature);
    return publicKey.verify(md.digest().bytes(), signatureBytes);
  } catch {
    return false;
  }
}
