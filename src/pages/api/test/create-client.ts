import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 개발 환경에서만 허용
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Not allowed in production' });
  }

  try {
    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

    const clientId = randomBytes(16).toString('hex');
    const clientSecret = randomBytes(32).toString('hex');

    const client = await prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret,
        name: 'Test OAuth Client',
        redirectUris: [
          `${baseUrl}/test/oauth-client`,
          'http://localhost:3000/test/oauth-client',
          'http://localhost:3001/callback',
        ],
      },
    });

    return res.json({
      success: true,
      client: {
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        name: client.name,
        redirectUris: client.redirectUris,
      },
    });
  } catch (error) {
    console.error('Create test client error:', error);
    return res.status(500).json({ error: 'Failed to create client' });
  }
}
