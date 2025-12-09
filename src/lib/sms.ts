const SOLAPI_API_KEY = process.env.SOLAPI_API_KEY || '';
const SOLAPI_API_SECRET = process.env.SOLAPI_API_SECRET || '';
const SOLAPI_SENDER = process.env.SOLAPI_SENDER || '';

// 6자리 인증 코드 생성
export function generateVerificationCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// SMS 발송
export async function sendSMS(to: string, text: string): Promise<boolean> {
  const cleanPhone = to.replace(/[^0-9]/g, '');

  console.log('[SMS] 설정 확인:', {
    apiKey: SOLAPI_API_KEY ? `${SOLAPI_API_KEY.substring(0, 4)}...` : '없음',
    apiSecret: SOLAPI_API_SECRET ? '설정됨' : '없음',
    sender: SOLAPI_SENDER || '없음',
  });

  // API 키가 없으면 개발 모드로 동작
  if (!SOLAPI_API_KEY || !SOLAPI_API_SECRET || !SOLAPI_SENDER) {
    console.log('[SMS] API 키 미설정 - 시뮬레이션 모드');
    console.log('[SMS] 발송 시뮬레이션:', { to: cleanPhone, text });
    return true;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { SolapiMessageService } = require('solapi');

    console.log('[SMS] SolapiMessageService 로드 완료');

    const messageService = new SolapiMessageService(SOLAPI_API_KEY, SOLAPI_API_SECRET);

    console.log('[SMS] 발송 시도:', { to: cleanPhone, from: SOLAPI_SENDER, textLength: text.length });

    const result = await messageService.send({
      to: cleanPhone,
      from: SOLAPI_SENDER,
      text: text,
    });

    console.log('[SMS] 발송 성공:', JSON.stringify(result, null, 2));
    return true;
  } catch (error: any) {
    console.error('[SMS] 발송 실패 - 전체 에러:', error);
    console.error('[SMS] 에러 타입:', typeof error);
    console.error('[SMS] 에러 이름:', error?.name);
    console.error('[SMS] 에러 메시지:', error?.message);
    console.error('[SMS] 에러 스택:', error?.stack);

    if (error?.response) {
      console.error('[SMS] 응답 상태:', error.response.status);
      console.error('[SMS] 응답 데이터:', JSON.stringify(error.response.data, null, 2));
    }

    return false;
  }
}

// 인증 코드 SMS 발송
export async function sendVerificationSMS(phone: string, code: string): Promise<boolean> {
  const text = `[2Check] 인증번호 [${code}] 3분내 입력`;
  return sendSMS(phone, text);
}
