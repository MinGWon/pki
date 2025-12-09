import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    const clients = await prisma.oAuthClient.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return res.json(clients);
  }

  if (req.method === 'POST') {
    const { name, redirectUris } = req.body;

    const clientId = randomBytes(16).toString('hex');
    const clientSecret = randomBytes(32).toString('hex');

    const client = await prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret,
        name,
        redirectUris: redirectUris || [],
      },
    });

    return res.status(201).json(client);
  }

  if (req.method === 'DELETE') {
    const { id } = req.query;
    await prisma.oAuthClient.delete({ where: { id: id as string } });
    return res.json({ success: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
