/**
 * 전화번호 포맷팅 (010-xxxx-xxxx)
 * @param value 입력값
 * @returns 포맷팅된 전화번호
 */
export function formatPhoneNumber(value: string): string {
  // 숫자만 추출
  const numbers = value.replace(/[^0-9]/g, '');
  
  // 최대 11자리
  const limited = numbers.slice(0, 11);
  
  // 하이픈 추가
  if (limited.length <= 3) {
    return limited;
  } else if (limited.length <= 7) {
    return `${limited.slice(0, 3)}-${limited.slice(3)}`;
  } else {
    return `${limited.slice(0, 3)}-${limited.slice(3, 7)}-${limited.slice(7)}`;
  }
}
