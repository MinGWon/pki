import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { page = '1', limit = '50', action } = req.query;

  const where: any = {};
  if (action) where.action = action;

  const pageNum = parseInt(page as string);
  const limitNum = parseInt(limit as string);

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (pageNum - 1) * limitNum,
      take: limitNum,
    }),
    prisma.auditLog.count({ where }),
  ]);

  return res.json({
    logs,
    pagination: {
      page: pageNum,
      limit: limitNum,
      total,
      totalPages: Math.ceil(total / limitNum),
    },
  });
}
