import type { NextApiRequest, NextApiResponse } from 'next';
import { verificationStore } from './send';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { phone, code } = req.body;

    if (!phone || !code) {
      return res.status(400).json({ error: '전화번호와 인증 코드를 입력해주세요.' });
    }

    const cleanPhone = phone.replace(/[^0-9]/g, '');

    // 메모리에서 조회
    const verification = verificationStore.get(cleanPhone);

    if (!verification) {
      return res.status(400).json({ error: '인증 코드를 먼저 요청해주세요.' });
    }

    // 만료 확인
    if (verification.expiresAt < new Date()) {
      verificationStore.delete(cleanPhone);
      return res.status(400).json({ error: '인증 코드가 만료되었습니다.' });
    }

    // 코드 일치 확인
    if (verification.code !== code) {
      return res.status(400).json({ error: '인증 코드가 일치하지 않습니다.' });
    }

    // 인증 성공 - 코드 삭제
    verificationStore.delete(cleanPhone);

    console.log('[SMS] 인증 성공:', cleanPhone);

    return res.status(200).json({ 
      success: true, 
      verified: true,
      phone: cleanPhone,
    });
  } catch (error) {
    console.error('[SMS] 인증 오류:', error);
    return res.status(500).json({ error: '인증 실패' });
  }
}
