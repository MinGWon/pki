import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 관리자 인증
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { name, redirectUris } = req.body;

    if (!name || !redirectUris || !Array.isArray(redirectUris)) {
      return res.status(400).json({ error: 'Name and redirectUris are required' });
    }

    const clientId = randomBytes(16).toString('hex');
    const clientSecret = randomBytes(32).toString('hex');

    const client = await prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret,
        name,
        redirectUris,
      },
    });

    await prisma.auditLog.create({
      data: {
        action: 'OAUTH_CLIENT_REGISTERED',
        clientId,
        details: { name, redirectUris },
      },
    });

    return res.status(201).json({
      success: true,
      client: {
        id: client.id,
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        name: client.name,
        redirectUris: client.redirectUris,
      },
    });
  } catch (error) {
    console.error('Client registration error:', error);
    return res.status(500).json({ error: 'Failed to register client' });
  }
}
