import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;

  if (req.method === 'GET') {
    try {
      const certificate = await prisma.certificate.findUnique({
        where: { id: id as string },
        include: {
          user: {
            select: { id: true, email: true, name: true },
          },
        },
      });

      if (!certificate) {
        return res.status(404).json({ error: 'Certificate not found' });
      }

      return res.json({ certificate });
    } catch (error) {
      console.error('Certificate detail error:', error);
      return res.status(500).json({ error: 'Failed to fetch certificate' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
