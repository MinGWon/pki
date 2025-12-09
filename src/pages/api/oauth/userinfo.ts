import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { verifyJWT } from '@/lib/jwt';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  console.log('[userinfo] ========== 요청 시작 ==========');

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
    console.log('[userinfo] JWT payload:', JSON.stringify(payload, null, 2));

    if (!payload) {
      console.log('[userinfo] JWT verification failed');
      return res.status(401).json({ error: 'invalid_token', error_description: 'JWT verification failed' });
    }

    console.log('[userinfo] 사용자 조회 중... userId:', payload.sub);
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
    });

    console.log('[userinfo] User 조회 결과:', user ? JSON.stringify({ id: user.id, name: user.name, email: user.email }) : 'null');

    if (!user) {
      return res.status(401).json({ error: 'invalid_token', error_description: 'User not found' });
    }

    // 사용자의 인증서 조회
    console.log('[userinfo] 인증서 조회 중... userId:', user.id);
    const certificate = await prisma.certificate.findFirst({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
    });

    console.log('[userinfo] Certificate 조회 결과:', certificate ? JSON.stringify({
      id: certificate.id,
      serialNumber: certificate.serialNumber?.substring(0, 16) + '...',
      status: certificate.status,
      notAfter: certificate.notAfter,
    }) : 'null');

    const response = {
      sub: user.id,
      name: user.name,
      email: user.email,
      certificate_id: certificate?.id || null,
      certificate_status: certificate?.status || null,
      certificate_expires: certificate?.notAfter?.toISOString() || null,
    };

    console.log('[userinfo] 응답:', JSON.stringify(response, null, 2));
    console.log('[userinfo] ========== 요청 완료 ==========');

    return res.json(response);
  } catch (error) {
    console.error('[userinfo] Error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}
