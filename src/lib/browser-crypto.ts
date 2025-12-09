/**
 * 브라우저 WebCrypto API 기반 암호화 유틸리티
 * 주의: 이 파일은 클라이언트 사이드에서만 사용
 */

// Base64 인코딩/디코딩
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// SHA-256 해시
export async function sha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return arrayBufferToBase64(hashBuffer);
}

// RSA 키페어 생성
export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
}

// RSA 서명 생성
export async function signWithRSA(
  privateKey: CryptoKey,
  data: string
): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    dataBuffer
  );
  
  return arrayBufferToBase64(signature);
}

// RSA 서명 검증
export async function verifyWithRSA(
  publicKey: CryptoKey,
  data: string,
  signature: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const signatureBuffer = base64ToArrayBuffer(signature);
  
  return await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    signatureBuffer,
    dataBuffer
  );
}

// PEM to CryptoKey 변환 (공개키)
export async function importPublicKeyFromPEM(pem: string): Promise<CryptoKey> {
  // PEM 헤더/푸터 제거
  const pemContents = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/-----BEGIN RSA PUBLIC KEY-----/, '')
    .replace(/-----END RSA PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  return await crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    true,
    ['verify']
  );
}

// CryptoKey to PEM 변환 (공개키)
export async function exportPublicKeyToPEM(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('spki', key);
  const base64 = arrayBufferToBase64(exported);
  
  // 64자씩 줄바꿈
  const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
  
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

// 랜덤 바이트 생성
export function generateRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

// 랜덤 문자열 생성 (Base64 URL-safe)
export function generateRandomString(length: number): string {
  const bytes = generateRandomBytes(length);
  const buffer = new ArrayBuffer(bytes.length);
  const view = new Uint8Array(buffer);
  view.set(bytes);
  
  return arrayBufferToBase64(buffer)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
    .substring(0, length);
}
