import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { clientId } = req.query;

  if (!clientId || typeof clientId !== 'string') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_id is required' });
  }

  // default 클라이언트는 항상 유효
  if (clientId === 'default') {
    return res.status(200).json({ valid: true });
  }

  try {
    const client = await prisma.oAuthClient.findUnique({
      where: { clientId },
      select: { clientId: true, name: true },
    });

    if (!client) {
      console.log('[validate] Client not found:', clientId);
      return res.status(404).json({ error: 'invalid_client', error_description: 'Client not found' });
    }

    console.log('[validate] Client valid:', clientId);
    return res.status(200).json({ valid: true, name: client.name });
  } catch (error) {
    console.error('[validate] Error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}
