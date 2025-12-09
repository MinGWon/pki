import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { verifyJWT } from '@/lib/jwt';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { token } = req.body;

    if (!token) {
      return res.json({ active: false });
    }

    // JWT 검증
    const payload = await verifyJWT(token);

    if (!payload) {
      return res.json({ active: false });
    }

    // 사용자 조회
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      return res.json({ active: false });
    }

    return res.json({
      active: true,
      sub: payload.sub,
      client_id: payload.client_id,
      email: payload.email,
      name: payload.name,
      scope: payload.scope,
      token_type: 'Bearer',
    });
  } catch (error) {
    console.error('Token introspect error:', error);
    return res.json({ active: false });
  }
}
