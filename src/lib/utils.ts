import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { verifyJWT } from '@/lib/jwt';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const authHeader = req.headers.authorization;
    console.log('[userinfo] Authorization header:', authHeader ? `Bearer ${authHeader.substring(7, 20)}...` : 'none');

    if (!authHeader?.startsWith('Bearer ')) {
      console.log('[userinfo] Missing or invalid Bearer token');
      return res.status(401).json({ error: 'invalid_token', error_description: 'Missing Bearer token' });
    }

    const token = authHeader.substring(7);
    console.log('[userinfo] Token length:', token.length);

    const payload = await verifyJWT(token);
    console.log('[userinfo] JWT payload:', payload);

    if (!payload) {
      console.log('[userinfo] JWT verification failed');
      return res.status(401).json({ error: 'invalid_token', error_description: 'JWT verification failed' });
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
    });

    console.log('[userinfo] User found:', user ? user.id : 'not found');

    if (!user) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'User not found' });
    }

    // 사용자의 인증서 조회
    const certificate = await prisma.certificate.findFirst({
      where: { userId: user.id },
      select: { id: true },
      orderBy: { createdAt: 'desc' },
    });

    return res.json({
      sub: user.id,
      name: user.name,
      certificate_id: certificate?.id || null,
    });
  } catch (error) {
    console.error('[userinfo] Error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}