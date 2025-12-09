/**
 * 한글을 ASCII 안전한 형식으로 인코딩
 * @param text 원본 텍스트 (한글 포함 가능)
 * @returns ASCII 안전한 문자열
 */
export function encodeToAscii(text: string): string {
  // 한글이 포함되어 있으면 Base64로 인코딩
  if (/[가-힣ㄱ-ㅎㅏ-ㅣ]/.test(text)) {
    const encoded = Buffer.from(text, 'utf-8').toString('base64');
    return `B64_${encoded}`;
  }
  return text;
}

/**
 * ASCII 인코딩된 문자열을 원본으로 디코딩
 * @param encoded 인코딩된 문자열
 * @returns 원본 텍스트
 */
export function decodeFromAscii(encoded: string): string {
  if (encoded.startsWith('B64_')) {
    const base64 = encoded.substring(4);
    return Buffer.from(base64, 'base64').toString('utf-8');
  }
  return encoded;
}

/**
 * subjectDN에서 CN 값을 추출하고 디코딩
 * @param subjectDN 예: "CN=B64_7ZmN6ri467F0, O=2Check, C=KR"
 * @returns 디코딩된 이름 예: "홍길동"
 */
export function extractAndDecodeCN(subjectDN: string): string {
  const match = subjectDN.match(/CN=([^,]+)/);
  if (!match) return subjectDN;
  return decodeFromAscii(match[1].trim());
}

/**
 * 원본 이름으로 ASCII 안전한 subjectDN 생성
 * @param name 원본 이름 (한글 가능)
 * @param org 조직명
 * @param country 국가코드
 * @returns ASCII 안전한 subjectDN
 */
export function buildAsciiSubjectDN(name: string, org: string = '2Check', country: string = 'KR'): string {
  const encodedName = encodeToAscii(name);
  return `CN=${encodedName}, O=${org}, C=${country}`;
}
