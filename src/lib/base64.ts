/**
 * URL-safe Base64를 표준 Base64로 변환
 */
export function urlSafeToStandard(base64url: string): string {
  return base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(base64url.length + (4 - (base64url.length % 4)) % 4, '=');
}

/**
 * 표준 Base64를 URL-safe Base64로 변환
 */
export function standardToUrlSafe(base64: string): string {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64 문자열 정규화 (공백, 줄바꿈 제거 및 패딩 수정)
 */
export function normalizeBase64(base64: string): string {
  // 공백, 줄바꿈 제거
  let cleaned = base64.replace(/\s/g, '');
  
  // URL-safe 문자 변환
  cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/');
  
  // 패딩 수정
  const remainder = cleaned.length % 4;
  if (remainder === 2) {
    cleaned += '==';
  } else if (remainder === 3) {
    cleaned += '=';
  }
  
  return cleaned;
}

/**
 * 안전한 Base64 디코딩
 */
export function safeBase64Decode(base64: string): Buffer {
  const normalized = normalizeBase64(base64);
  return Buffer.from(normalized, 'base64');
}
