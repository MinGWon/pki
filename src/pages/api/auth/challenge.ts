import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 32바이트 랜덤 챌린지 생성 (표준 Base64)
    const challengeBytes = randomBytes(32);
    const challenge = challengeBytes.toString('base64');

    const expiresAt = new Date(Date.now() + (parseInt(process.env.CHALLENGE_EXPIRY_SECONDS || '300') * 1000));

    // DB에 저장
    await prisma.challenge.create({
      data: {
        challenge,
        expiresAt,
      },
    });

    console.log('[CHALLENGE] 생성됨:', challenge);

    return res.json({ 
      challenge,
      expiresAt: expiresAt.toISOString(),
    });
  } catch (error) {
    console.error('Challenge generation error:', error);
    return res.status(500).json({ error: 'Failed to generate challenge' });
  }
}
