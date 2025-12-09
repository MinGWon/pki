import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') {
    const { page = '1', limit = '20', status } = req.query;

    const where: any = {};
    if (status) where.status = status;

    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);

    const [certificates, total] = await Promise.all([
      prisma.certificate.findMany({
        where,
        include: { user: { select: { name: true, email: true } } },
        orderBy: { createdAt: 'desc' },
        skip: (pageNum - 1) * limitNum,
        take: limitNum,
      }),
      prisma.certificate.count({ where }),
    ]);

    return res.json({
      certificates,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  }

  if (req.method === 'PATCH') {
    const { id, status } = req.body;

    const certificate = await prisma.certificate.update({
      where: { id },
      data: { status },
    });

    if (status === 'REVOKED') {
      await prisma.revokedCertificate.create({
        data: {
          serialNumber: certificate.serialNumber,
          reason: 'Admin revoked',
        },
      });
    }

    return res.json(certificate);
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
