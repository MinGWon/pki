import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const clients = await prisma.oAuthClient.findMany({
      select: {
        id: true,
        clientId: true,
        name: true,
        redirectUris: true,
        createdAt: true,
      },
    });

    return res.json({ clients });
  } catch (error) {
    console.error('Client list error:', error);
    return res.status(500).json({ error: 'Failed to fetch clients' });
  }
}
