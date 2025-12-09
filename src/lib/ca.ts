import forge from 'node-forge';
import { getSigningCA } from './ca-store';

export interface CertificateInfo {
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  publicKeyPem: string;
  privateKeyPem: string;
  certificatePem: string;
  notBefore: Date;
  notAfter: Date;
}

export interface SubjectInfo {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
}

// 속성 배열을 DN 문자열로 변환하는 헬퍼 함수
function attributesToDN(attributes: forge.pki.CertificateField[]): string {
  return attributes
    .map((a) => `${a.shortName || a.name}=${a.value}`)
    .join(', ');
}

// 시리얼 넘버 생성
function generateSerialNumber(): string {
  const bytes = forge.random.getBytesSync(16);
  return forge.util.bytesToHex(bytes).toUpperCase();
}

// Subject DN 문자열 생성
function buildSubjectDN(subject: SubjectInfo): string {
  const parts: string[] = [];
  if (subject.commonName) parts.push(`CN=${subject.commonName}`);
  if (subject.organizationalUnit) parts.push(`OU=${subject.organizationalUnit}`);
  if (subject.organization) parts.push(`O=${subject.organization}`);
  if (subject.locality) parts.push(`L=${subject.locality}`);
  if (subject.state) parts.push(`ST=${subject.state}`);
  if (subject.country) parts.push(`C=${subject.country}`);
  return parts.join(', ');
}

// PEM 형식 정규화 (공백, 잘못된 줄바꿈 제거)
function normalizePem(pem: string): string {
  // 1. 모든 종류의 줄바꿈을 \n으로 통일
  let normalized = pem.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  
  // 2. 각 줄의 앞뒤 공백 제거
  const lines = normalized.split('\n').map(line => line.trim());
  
  // 3. 빈 줄 제거 (BEGIN/END 사이)
  const result: string[] = [];
  let inCert = false;
  
  for (const line of lines) {
    if (line.includes('-----BEGIN')) {
      inCert = true;
      result.push(line);
    } else if (line.includes('-----END')) {
      inCert = false;
      result.push(line);
    } else if (inCert && line.length > 0) {
      result.push(line);
    } else if (!inCert && line.length > 0) {
      result.push(line);
    }
  }
  
  return result.join('\n');
}

// 한글을 ASCII로 변환 (Punycode 스타일)
function toAsciiName(name: string): string {
  // 한글이 포함되어 있으면 Base64로 인코딩
  if (/[가-힣]/.test(name)) {
    const encoded = Buffer.from(name, 'utf-8').toString('base64');
    return `B64_${encoded}`;
  }
  return name;
}

// ASCII 이름을 한글로 복원
export function fromAsciiName(asciiName: string): string {
  if (asciiName.startsWith('B64_')) {
    const base64 = asciiName.substring(4);
    return Buffer.from(base64, 'base64').toString('utf-8');
  }
  return asciiName;
}

// 루트 CA 인증서 생성
export function generateRootCA(
  subject: SubjectInfo,
  validityYears: number = 10
): CertificateInfo {
  const keys = forge.pki.rsa.generateKeyPair(4096);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = generateSerialNumber();

  const now = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(now.getFullYear() + validityYears);

  cert.validity.notBefore = now;
  cert.validity.notAfter = notAfter;

  const attrs = [
    { name: 'commonName', value: subject.commonName },
    { name: 'organizationName', value: subject.organization || '2Check' },
    { name: 'countryName', value: subject.country || 'KR' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    serialNumber: cert.serialNumber,
    subjectDN: buildSubjectDN(subject),
    issuerDN: buildSubjectDN(subject),
    publicKeyPem: forge.pki.publicKeyToPem(keys.publicKey),
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certificatePem: forge.pki.certificateToPem(cert),
    notBefore: now,
    notAfter,
  };
}

// 중간 CA 인증서 생성
export function generateIntermediateCA(
  subject: SubjectInfo,
  rootCertPem: string,
  rootKeyPem: string,
  validityYears: number = 5
): CertificateInfo {
  const rootCert = forge.pki.certificateFromPem(rootCertPem);
  const rootKey = forge.pki.privateKeyFromPem(rootKeyPem);

  const keys = forge.pki.rsa.generateKeyPair(4096);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = generateSerialNumber();

  const now = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(now.getFullYear() + validityYears);

  cert.validity.notBefore = now;
  cert.validity.notAfter = notAfter;

  const attrs = [
    { name: 'commonName', value: subject.commonName },
    { name: 'organizationName', value: subject.organization || '2Check' },
    { name: 'countryName', value: subject.country || 'KR' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(rootCert.subject.attributes);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(rootKey, forge.md.sha256.create());

  const issuerDN = attributesToDN(rootCert.subject.attributes);

  return {
    serialNumber: cert.serialNumber,
    subjectDN: buildSubjectDN(subject),
    issuerDN,
    publicKeyPem: forge.pki.publicKeyToPem(keys.publicKey),
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certificatePem: forge.pki.certificateToPem(cert),
    notBefore: now,
    notAfter,
  };
}

// 사용자 인증서 생성
export function generateUserCertificate(
  subject: SubjectInfo,
  caCertPem: string,
  caKeyPem: string,
  validityYears: number = 1
): CertificateInfo {
  console.log('[USER CERT DEBUG] 시작');
  
  // PEM 정규화
  const normalizedCaCert = normalizePem(caCertPem);
  const normalizedCaKey = normalizePem(caKeyPem);

  const caCert = forge.pki.certificateFromPem(normalizedCaCert);
  const caKey = forge.pki.privateKeyFromPem(normalizedCaKey);

  console.log('[USER CERT DEBUG] CA 인증서/키 파싱 성공');

  const keys = forge.pki.rsa.generateKeyPair(2048);
  console.log('[USER CERT DEBUG] RSA 키페어 생성 완료');

  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = generateSerialNumber();

  const now = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(now.getFullYear() + validityYears);

  cert.validity.notBefore = now;
  cert.validity.notAfter = notAfter;

  // 한글을 ASCII로 변환하여 인증서 내부에 저장 (호환성)
  const asciiCommonName = toAsciiName(subject.commonName);
  const asciiOrganization = subject.organization ? toAsciiName(subject.organization) : undefined;

  console.log('[USER CERT DEBUG] 원본 이름:', subject.commonName);
  console.log('[USER CERT DEBUG] ASCII 변환:', asciiCommonName);

  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: asciiCommonName },
  ];
  if (asciiOrganization) {
    attrs.push({ name: 'organizationName', value: asciiOrganization });
  }
  if (subject.country) {
    attrs.push({ name: 'countryName', value: subject.country });
  }

  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  const extensions: any[] = [
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, nonRepudiation: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
    { name: 'subjectKeyIdentifier' },
  ];

  if (subject.email) {
    extensions.push({
      name: 'subjectAltName',
      altNames: [{ type: 1, value: subject.email }],
    });
  }

  cert.setExtensions(extensions);
  cert.sign(caKey, forge.md.sha256.create());

  console.log('[USER CERT DEBUG] 인증서 서명 완료');

  const issuerDN = attributesToDN(caCert.subject.attributes);
  
  // PEM 생성
  const certificatePem = forge.pki.certificateToPem(cert);
  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);

  console.log('[USER CERT DEBUG] PEM 변환 완료');
  console.log('[USER CERT DEBUG] certificatePem 길이:', certificatePem.length);

  // subjectDN은 원본 한글로 반환 (DB 및 API용)
  return {
    serialNumber: cert.serialNumber,
    subjectDN: buildSubjectDN(subject), // 원본 한글 유지
    issuerDN,
    publicKeyPem,
    privateKeyPem,
    certificatePem,
    notBefore: now,
    notAfter,
  };
}

// PKCS#12 파일 생성
export function generatePKCS12(
  certPem: string,
  keyPem: string,
  password: string,
  _caCertPem?: string
): Buffer {
  console.log('[PKCS12 DEBUG] ========== 시작 ==========');
  
  // PEM 정규화
  const normalizedCertPem = normalizePem(certPem);
  const normalizedKeyPem = normalizePem(keyPem);
  
  console.log('[PKCS12 DEBUG] 정규화 후 certPem 길이:', normalizedCertPem.length);
  console.log('[PKCS12 DEBUG] 정규화 후 keyPem 길이:', normalizedKeyPem.length);
  
  // 디버그: PEM 내용 출력
  console.log('[PKCS12 DEBUG] certPem 첫 100자:', normalizedCertPem.substring(0, 100));
  console.log('[PKCS12 DEBUG] certPem 마지막 50자:', normalizedCertPem.substring(normalizedCertPem.length - 50));

  // PEM 형식 확인
  if (!normalizedCertPem.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('certPem is not in PEM format');
  }
  if (!normalizedKeyPem.includes('-----BEGIN RSA PRIVATE KEY-----') && 
      !normalizedKeyPem.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('keyPem is not in PEM format');
  }

  // 1. 인증서 파싱
  console.log('[PKCS12 DEBUG] 인증서 파싱 시작');
  let cert;
  try {
    cert = forge.pki.certificateFromPem(normalizedCertPem);
    console.log('[PKCS12 DEBUG] 인증서 파싱 성공, serialNumber:', cert.serialNumber);
  } catch (e) {
    console.error('[PKCS12 DEBUG] 인증서 파싱 실패:', e);
    console.error('[PKCS12 DEBUG] 정규화된 certPem 전체:');
    console.error(normalizedCertPem);
    throw new Error(`Certificate parsing failed: ${e}`);
  }

  // 2. 개인키 파싱
  console.log('[PKCS12 DEBUG] 개인키 파싱 시작');
  let key;
  try {
    key = forge.pki.privateKeyFromPem(normalizedKeyPem);
    console.log('[PKCS12 DEBUG] 개인키 파싱 성공');
  } catch (e) {
    console.error('[PKCS12 DEBUG] 개인키 파싱 실패:', e);
    throw new Error(`Private key parsing failed: ${e}`);
  }

  // 3. PKCS#12 ASN.1 생성
  console.log('[PKCS12 DEBUG] PKCS12 ASN.1 생성 시작');
  let p12Asn1;
  try {
    p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, cert, password, {
      algorithm: '3des',  // 3DES (호환성 최적)
      count: 100000,      // PBKDF2 iteration count
    });
    console.log('[PKCS12 DEBUG] PKCS12 ASN.1 생성 성공 (3DES)');
  } catch (e) {
    console.error('[PKCS12 DEBUG] PKCS12 ASN.1 생성 실패:', e);
    throw new Error(`PKCS12 ASN.1 generation failed: ${e}`);
  }

  // 4. DER 변환
  console.log('[PKCS12 DEBUG] DER 변환 시작');
  let p12Der;
  try {
    p12Der = forge.asn1.toDer(p12Asn1).getBytes();
    console.log('[PKCS12 DEBUG] DER 변환 성공, 길이:', p12Der.length);
  } catch (e) {
    console.error('[PKCS12 DEBUG] DER 변환 실패:', e);
    throw new Error(`DER conversion failed: ${e}`);
  }

  // 5. Buffer 변환
  const buffer = Buffer.alloc(p12Der.length);
  for (let i = 0; i < p12Der.length; i++) {
    buffer[i] = p12Der.charCodeAt(i);
  }
  console.log('[PKCS12 DEBUG] 완료, 버퍼 크기:', buffer.length);

  return buffer;
}

// 인증서 정보 파싱
export function parseCertificate(certPem: string): {
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyPem: string;
} {
  const cert = forge.pki.certificateFromPem(certPem);

  const subjectDN = attributesToDN(cert.subject.attributes);
  const issuerDN = attributesToDN(cert.issuer.attributes);

  return {
    serialNumber: cert.serialNumber,
    subjectDN,
    issuerDN,
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
    publicKeyPem: forge.pki.publicKeyToPem(cert.publicKey),
  };
}

// 사용자 인증서 발급 통합 함수
export interface IssueCertificateParams {
  commonName: string;
  email?: string;
  userId: string;
  password: string;
  validityYears?: number;
}

export interface IssueCertificateResult {
  serialNumber: string;
  subjectDN: string;
  issuerDN: string;
  notBefore: string;
  notAfter: string;
  publicKeyPem: string;
  p12Base64: string;
}

export async function issueCertificate(params: IssueCertificateParams): Promise<IssueCertificateResult> {
  console.log('[issueCertificate] 시작:', params.commonName);

  // 1. CA 정보 가져오기
  const signingCA = getSigningCA();
  if (!signingCA) {
    throw new Error('CA가 초기화되지 않았습니다. /test 페이지에서 CA 초기화를 먼저 실행하세요.');
  }

  console.log('[issueCertificate] CA 로드 완료');

  // 2. 사용자 인증서 생성
  const certInfo = generateUserCertificate(
    {
      commonName: params.commonName,
      email: params.email,
      organization: '2Check',
      country: 'KR',
    },
    signingCA.certPem,
    signingCA.keyPem,
    params.validityYears || 1
  );

  console.log('[issueCertificate] 인증서 생성 완료, serialNumber:', certInfo.serialNumber);

  // 3. PKCS#12 생성
  const p12Buffer = generatePKCS12(
    certInfo.certificatePem,
    certInfo.privateKeyPem,
    params.password,
    signingCA.certPem
  );

  console.log('[issueCertificate] PKCS#12 생성 완료, 크기:', p12Buffer.length);

  return {
    serialNumber: certInfo.serialNumber,
    subjectDN: certInfo.subjectDN,
    issuerDN: certInfo.issuerDN,
    notBefore: certInfo.notBefore.toISOString(),
    notAfter: certInfo.notAfter.toISOString(),
    publicKeyPem: certInfo.publicKeyPem,
    p12Base64: p12Buffer.toString('base64'),
  };
}
