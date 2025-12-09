import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { hashPhoneNumber } from '@/lib/hash';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { name, phone, email } = req.body;

    if (!name || !phone) {
      return res.status(400).json({ error: '이름과 전화번호는 필수입니다.' });
    }

    const cleanPhone = phone.replace(/[^0-9]/g, '');
    const userId = hashPhoneNumber(cleanPhone);

    // 기존 사용자 확인
    let user = await prisma.user.findUnique({ where: { id: userId } });

    if (user) {
      // 기존 사용자 정보 업데이트
      user = await prisma.user.update({
        where: { id: userId },
        data: { name, email: email || null },
      });
    } else {
      // 새 사용자 생성
      user = await prisma.user.create({
        data: {
          id: userId,
          name,
          phone: cleanPhone,
          email: email || null,
        },
      });
    }

    console.log('[register] 사용자 등록/업데이트:', user.id);

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('[register] Error:', error);
    return res.status(500).json({ error: '사용자 등록 실패' });
  }
}
