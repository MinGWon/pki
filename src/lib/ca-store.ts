import fs from 'fs';
import path from 'path';
import forge from 'node-forge';

const CA_STORE_PATH = process.env.CA_STORE_PATH || path.join(process.cwd(), 'ca-store');

interface CAConfig {
  rootCert: string;
  rootKey: string;
  intermediateCert: string;
  intermediateKey: string;
}

// 파싱된 CA 키 캐시
let cachedSigningCA: {
  certPem: string;
  keyPem: string;
  cert: forge.pki.Certificate;
  key: forge.pki.PrivateKey;
} | null = null;

// CA 저장소 초기화
export function initCAStore(): void {
  if (!fs.existsSync(CA_STORE_PATH)) {
    fs.mkdirSync(CA_STORE_PATH, { recursive: true });
  }
}

// CA 설정 저장
export function saveCAConfig(config: CAConfig): void {
  initCAStore();
  fs.writeFileSync(path.join(CA_STORE_PATH, 'root.crt'), config.rootCert);
  fs.writeFileSync(path.join(CA_STORE_PATH, 'root.key'), config.rootKey, { mode: 0o600 });
  fs.writeFileSync(path.join(CA_STORE_PATH, 'intermediate.crt'), config.intermediateCert);
  fs.writeFileSync(path.join(CA_STORE_PATH, 'intermediate.key'), config.intermediateKey, { mode: 0o600 });
}

// CA 설정 로드
export function loadCAConfig(): CAConfig | null {
  try {
    return {
      rootCert: fs.readFileSync(path.join(CA_STORE_PATH, 'root.crt'), 'utf-8'),
      rootKey: fs.readFileSync(path.join(CA_STORE_PATH, 'root.key'), 'utf-8'),
      intermediateCert: fs.readFileSync(path.join(CA_STORE_PATH, 'intermediate.crt'), 'utf-8'),
      intermediateKey: fs.readFileSync(path.join(CA_STORE_PATH, 'intermediate.key'), 'utf-8'),
    };
  } catch {
    return null;
  }
}

// CA 초기화 여부 확인
export function isCAInitialized(): boolean {
  return loadCAConfig() !== null;
}

// 서명용 CA (중간 CA) 가져오기
export function getSigningCA(): { certPem: string; keyPem: string } | null {
  const config = loadCAConfig();
  if (!config) return null;
  return {
    certPem: config.intermediateCert,
    keyPem: config.intermediateKey,
  };
}

// 인증서 체인 가져오기
export function getCertificateChain(): string | null {
  const config = loadCAConfig();
  if (!config) return null;
  return config.intermediateCert + '\n' + config.rootCert;
}

// 파싱된 서명용 CA 가져오기 (캐시)
export function getParsedSigningCA(): {
  cert: forge.pki.Certificate;
  key: forge.pki.PrivateKey;
} | null {
  if (cachedSigningCA) {
    return { cert: cachedSigningCA.cert, key: cachedSigningCA.key };
  }

  const config = loadCAConfig();
  if (!config) return null;

  try {
    const cert = forge.pki.certificateFromPem(config.intermediateCert);
    const key = forge.pki.privateKeyFromPem(config.intermediateKey);
    
    cachedSigningCA = {
      certPem: config.intermediateCert,
      keyPem: config.intermediateKey,
      cert,
      key,
    };
    
    console.log('[CA-STORE] CA 키 파싱 및 캐시 완료');
    return { cert, key };
  } catch (e) {
    console.error('[CA-STORE] CA 파싱 실패:', e);
    return null;
  }
}

// 캐시 초기화 (CA 재설정 시 호출)
export function clearCACache(): void {
  cachedSigningCA = null;
  console.log('[CA-STORE] CA 캐시 초기화');
}
