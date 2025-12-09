import type { NextApiRequest, NextApiResponse } from 'next';
import { generateVerificationCode, sendVerificationSMS } from '@/lib/sms';

// 임시 메모리 저장소 (프로덕션에서는 DB 사용)
const verificationStore = new Map<string, { code: string; expiresAt: Date }>();

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: '전화번호를 입력해주세요.' });
    }

    // 전화번호 정규화
    const cleanPhone = phone.replace(/[^0-9]/g, '');
    if (cleanPhone.length < 10) {
      return res.status(400).json({ error: '유효하지 않은 전화번호입니다.' });
    }

    // 인증 코드 생성
    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 3 * 60 * 1000); // 3분

    // 메모리에 저장
    verificationStore.set(cleanPhone, { code, expiresAt });

    // SMS 발송
    const sent = await sendVerificationSMS(cleanPhone, code);

    if (!sent) {
      return res.status(500).json({ error: 'SMS 발송에 실패했습니다.' });
    }

    console.log('[SMS] 인증 코드 발송:', cleanPhone, '(개발환경 코드:', code, ')');

    return res.status(200).json({ 
      success: true, 
      message: '인증 코드가 발송되었습니다.',
      // 개발 환경에서만 코드 반환
      ...(process.env.NODE_ENV === 'development' && { code }),
    });
  } catch (error) {
    console.error('[SMS] 발송 오류:', error);
    return res.status(500).json({ error: '인증 코드 발송 실패' });
  }
}

// 다른 API에서 사용할 수 있도록 export
export { verificationStore };
