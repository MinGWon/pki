import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

// 간소화된 OCSP 응답 (HTTP 기반)
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // GET: 간단한 상태 조회
  if (req.method === 'GET') {
    const { serialNumber } = req.query;

    if (!serialNumber) {
      return res.status(400).json({ error: 'serialNumber is required' });
    }

    try {
      // 인증서 조회
      const certificate = await prisma.certificate.findUnique({
        where: { serialNumber: serialNumber as string },
      });

      if (!certificate) {
        return res.json({
          serialNumber,
          status: 'unknown',
          message: 'Certificate not found in database',
        });
      }

      // 폐기 여부 확인
      const revoked = await prisma.revokedCertificate.findUnique({
        where: { serialNumber: serialNumber as string },
      });

      const now = new Date();
      let status: string;
      let reason: string | null = null;
      let revokedAt: Date | null = null;

      if (revoked) {
        status = 'revoked';
        reason = revoked.reason;
        revokedAt = revoked.revokedAt;
      } else if (now > certificate.notAfter) {
        status = 'expired';
      } else if (now < certificate.notBefore) {
        status = 'not_yet_valid';
      } else if (certificate.status === 'ACTIVE') {
        status = 'good';
      } else {
        status = certificate.status.toLowerCase();
      }

      // 감사 로그
      await prisma.auditLog.create({
        data: {
          action: 'OCSP_CHECK',
          details: { serialNumber, status },
          ipAddress: req.headers['x-forwarded-for'] as string || 'unknown',
        },
      });

      return res.json({
        serialNumber,
        status,
        reason,
        revokedAt,
        thisUpdate: new Date().toISOString(),
        nextUpdate: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1시간 후
        certificate: {
          subjectDN: certificate.subjectDN,
          issuerDN: certificate.issuerDN,
          notBefore: certificate.notBefore,
          notAfter: certificate.notAfter,
        },
      });
    } catch (error) {
      console.error('OCSP error:', error);
      return res.status(500).json({ error: 'OCSP check failed' });
    }
  }

  // POST: 표준 OCSP 요청 처리 (바이너리)
  if (req.method === 'POST') {
    // TODO: 표준 OCSP 프로토콜 구현 (RFC 6960)
    // 현재는 간소화된 버전만 지원
    return res.status(501).json({ 
      error: 'Binary OCSP not implemented',
      message: 'Use GET /api/ocsp?serialNumber=XXX for status check',
    });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
