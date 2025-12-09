import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const [
      userCount,
      certificateCount,
      activeCertCount,
      clientCount,
      recentLogs,
      recentCerts,
    ] = await Promise.all([
      prisma.user.count(),
      prisma.certificate.count(),
      prisma.certificate.count({ where: { status: 'ACTIVE' } }),
      prisma.oAuthClient.count(),
      prisma.auditLog.findMany({
        take: 20,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.certificate.findMany({
        take: 10,
        orderBy: { createdAt: 'desc' },
        include: { user: { select: { name: true, email: true } } },
      }),
    ]);

    return res.json({
      stats: {
        users: userCount,
        certificates: certificateCount,
        activeCertificates: activeCertCount,
        oauthClients: clientCount,
      },
      recentLogs,
      recentCertificates: recentCerts,
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    return res.status(500).json({ error: 'Failed to load dashboard' });
  }
}
