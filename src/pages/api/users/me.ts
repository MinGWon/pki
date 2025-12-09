import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { verifyJWT } from '@/lib/jwt';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);
    const payload = await verifyJWT(token);

    if (!payload) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({ user });
  } catch (error) {
    console.error('User me error:', error);
    return res.status(500).json({ error: 'Failed to fetch user' });
  }
}
