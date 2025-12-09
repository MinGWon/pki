import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { generateUserCertificate, generatePKCS12, parseCertificate } from '@/lib/ca';
import { getSigningCA } from '@/lib/ca-store';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { serialNumber, password, validityYears = 1 } = req.body;

    if (!serialNumber || !password) {
      return res.status(400).json({ error: 'Serial number and password are required' });
    }

    // 기존 인증서 조회
    const oldCert = await prisma.certificate.findUnique({
      where: { serialNumber },
      include: { user: true },
    });

    if (!oldCert) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    if (oldCert.status === 'REVOKED') {
      return res.status(400).json({ error: 'Cannot renew a revoked certificate' });
    }

    // 서명 CA 가져오기
    const signingCA = getSigningCA();
    if (!signingCA) {
      return res.status(500).json({ error: 'CA not initialized' });
    }

    // Subject 정보 파싱
    const cnMatch = oldCert.subjectDN.match(/CN=([^,]+)/);
    const emailMatch = oldCert.subjectDN.match(/emailAddress=([^,]+)/);

    // 새 인증서 생성
    const newCert = generateUserCertificate({
      commonName: cnMatch?.[1] || oldCert.user.name,
      email: emailMatch?.[1] || oldCert.user.email,
      organization: '2Check',
      country: 'KR',
    }, signingCA.certPem, signingCA.keyPem, validityYears);

    // PKCS#12 생성
    const p12Buffer = generatePKCS12(
      newCert.certificatePem,
      newCert.privateKeyPem,
      password,
      signingCA.certPem
    );

    // 기존 인증서 상태 변경
    await prisma.certificate.update({
      where: { id: oldCert.id },
      data: { status: 'RENEWED' },
    });

    // 새 인증서 DB 저장
    const certificate = await prisma.certificate.create({
      data: {
        userId: oldCert.userId,
        serialNumber: newCert.serialNumber,
        subjectDN: newCert.subjectDN,
        issuerDN: newCert.issuerDN,
        publicKey: newCert.publicKeyPem,
        notBefore: newCert.notBefore,
        notAfter: newCert.notAfter,
        status: 'ACTIVE',
      },
    });

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'CERTIFICATE_RENEWED',
        userId: oldCert.userId,
        details: {
          oldSerialNumber: serialNumber,
          newSerialNumber: newCert.serialNumber,
        },
      },
    });

    return res.json({
      success: true,
      certificate: {
        id: certificate.id,
        serialNumber: certificate.serialNumber,
        subjectDN: certificate.subjectDN,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      },
      p12: p12Buffer.toString('base64'),
    });
  } catch (error) {
    console.error('Certificate renew error:', error);
    return res.status(500).json({ error: 'Failed to renew certificate' });
  }
}
