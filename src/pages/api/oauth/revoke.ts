import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { token, token_type_hint } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    // access_token 또는 refresh_token으로 검색
    const oauthToken = await prisma.oAuthToken.findFirst({
      where: {
        OR: [
          { accessToken: token },
          { refreshToken: token },
        ],
      },
    });

    if (oauthToken) {
      await prisma.oAuthToken.delete({ where: { id: oauthToken.id } });

      await prisma.auditLog.create({
        data: {
          action: 'TOKEN_REVOKED',
          userId: oauthToken.userId,
          clientId: oauthToken.clientId,
        },
      });
    }

    // RFC 7009: 항상 200 반환 (토큰이 없어도)
    return res.status(200).json({});
  } catch (error) {
    console.error('Token revoke error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}
