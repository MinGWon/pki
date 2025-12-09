import crypto from 'crypto';

/**
 * 전화번호 해시 알고리즘 정보
 * - 알고리즘: SHA-256
 * - Salt: 고정 salt (환경변수로 관리)
 * - 출력: 32자리 hex 문자열
 * 
 * 해시 과정:
 * 1. 전화번호에서 숫자만 추출 (예: 010-1234-5678 -> 01012345678)
 * 2. salt + 전화번호를 합쳐서 SHA-256 해시
 * 3. 결과의 앞 32자리 사용
 */

// 고정 Salt - 환경변수로 관리 (프로덕션에서는 반드시 변경)
const PHONE_HASH_SALT = process.env.PHONE_HASH_SALT || '2check-pki-phone-salt-v1';

/**
 * 전화번호를 해시하여 고유한 userId 생성
 * @param phone 전화번호 (예: 010-1234-5678, 01012345678)
 * @returns 32자리 해시 문자열
 */
export function hashPhoneNumber(phone: string): string {
  // 전화번호에서 숫자만 추출
  const cleanPhone = phone.replace(/[^0-9]/g, '');
  
  if (cleanPhone.length < 10) {
    throw new Error('유효하지 않은 전화번호입니다.');
  }
  
  // Salt + 전화번호를 SHA-256 해시
  const hash = crypto
    .createHash('sha256')
    .update(PHONE_HASH_SALT + cleanPhone)
    .digest('hex');
  
  // 앞 32자리 반환
  return hash.substring(0, 32);
}

/**
 * 전화번호와 userId가 일치하는지 검증
 * @param phone 전화번호
 * @param userId 검증할 userId
 * @returns 일치 여부
 */
export function verifyPhoneHash(phone: string, userId: string): boolean {
  try {
    const hashedPhone = hashPhoneNumber(phone);
    return hashedPhone === userId;
  } catch {
    return false;
  }
}
