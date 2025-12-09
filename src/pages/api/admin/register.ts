import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { serialNumber, adminSecret } = req.body;

    // 관리자 시크릿 확인
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: 'Invalid admin secret' });
    }

    if (!serialNumber) {
      return res.status(400).json({ error: 'Serial number is required' });
    }

    // 인증서 조회
    const certificate = await prisma.certificate.findUnique({
      where: { serialNumber },
      include: { user: true },
    });

    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    // 사용자를 관리자로 등록
    await prisma.user.update({
      where: { id: certificate.userId },
      data: { isAdmin: true },
    });

    await prisma.auditLog.create({
      data: {
        action: 'ADMIN_REGISTERED',
        userId: certificate.userId,
        details: { serialNumber },
      },
    });

    return res.json({
      success: true,
      message: `${certificate.user.name}님이 관리자로 등록되었습니다.`,
    });
  } catch (error) {
    console.error('Admin register error:', error);
    return res.status(500).json({ error: 'Failed to register admin' });
  }
}
