import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { userId, status, page = '1', limit = '20' } = req.query;

    const where: any = {};
    if (userId) where.userId = userId;
    if (status) where.status = status;

    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    const [certificates, total] = await Promise.all([
      prisma.certificate.findMany({
        where,
        include: {
          user: {
            select: { id: true, email: true, name: true },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limitNum,
      }),
      prisma.certificate.count({ where }),
    ]);

    // 만료된 인증서 상태 자동 업데이트
    const now = new Date();
    const expiredIds = certificates
      .filter((c) => c.status === 'ACTIVE' && new Date(c.notAfter) < now)
      .map((c) => c.id);

    if (expiredIds.length > 0) {
      await prisma.certificate.updateMany({
        where: { id: { in: expiredIds } },
        data: { status: 'EXPIRED' },
      });
    }

    return res.json({
      certificates: certificates.map((c) => ({
        ...c,
        status: expiredIds.includes(c.id) ? 'EXPIRED' : c.status,
        publicKey: undefined, // 목록에서는 공개키 제외
      })),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (error) {
    console.error('Certificate list error:', error);
    return res.status(500).json({ error: 'Failed to fetch certificates' });
  }
}
