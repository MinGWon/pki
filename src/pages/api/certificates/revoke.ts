import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { serialNumber, reason } = req.body;

    if (!serialNumber) {
      return res.status(400).json({ error: 'Serial number is required' });
    }

    // 인증서 찾기
    const certificate = await prisma.certificate.findUnique({
      where: { serialNumber },
    });

    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    if (certificate.status === 'REVOKED') {
      return res.status(400).json({ error: 'Certificate already revoked' });
    }

    // 인증서 상태 업데이트
    await prisma.certificate.update({
      where: { serialNumber },
      data: { status: 'REVOKED' },
    });

    // 폐기 목록에 추가
    await prisma.revokedCertificate.create({
      data: { serialNumber, reason },
    });

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'CERTIFICATE_REVOKED',
        userId: certificate.userId,
        details: { serialNumber, reason },
      },
    });

    return res.json({ success: true });
  } catch (error) {
    console.error('Certificate revoke error:', error);
    return res.status(500).json({ error: 'Failed to revoke certificate' });
  }
}
