import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { loadCAConfig } from '@/lib/ca-store';
import forge from 'node-forge';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { certificatePem } = req.body;

    if (!certificatePem) {
      return res.status(400).json({ error: 'Certificate PEM is required' });
    }

    const caConfig = loadCAConfig();
    if (!caConfig) {
      return res.status(500).json({ error: 'CA not initialized' });
    }

    // 인증서 파싱
    let cert: forge.pki.Certificate;
    try {
      cert = forge.pki.certificateFromPem(certificatePem);
    } catch {
      return res.status(400).json({ 
        valid: false, 
        error: 'Invalid certificate format' 
      });
    }

    const serialNumber = cert.serialNumber;
    const now = new Date();
    const errors: string[] = [];

    // 1. 유효기간 검증
    if (now < cert.validity.notBefore) {
      errors.push('Certificate is not yet valid');
    }
    if (now > cert.validity.notAfter) {
      errors.push('Certificate has expired');
    }

    // 2. 발급자 체인 검증
    const intermediateCert = forge.pki.certificateFromPem(caConfig.intermediateCert);
    const rootCert = forge.pki.certificateFromPem(caConfig.rootCert);

    try {
      // 중간 CA로 서명 검증
      const caStore = forge.pki.createCaStore([intermediateCert, rootCert]);
      forge.pki.verifyCertificateChain(caStore, [cert]);
    } catch (chainError) {
      errors.push('Certificate chain verification failed');
    }

    // 3. 폐기 여부 확인
    const revoked = await prisma.revokedCertificate.findUnique({
      where: { serialNumber },
    });

    if (revoked) {
      errors.push(`Certificate was revoked: ${revoked.reason || 'unspecified'}`);
    }

    // 4. DB에서 상태 확인
    const dbCert = await prisma.certificate.findUnique({
      where: { serialNumber },
    });

    if (dbCert && dbCert.status !== 'ACTIVE') {
      errors.push(`Certificate status: ${dbCert.status}`);
    }

    const valid = errors.length === 0;

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'CERTIFICATE_VERIFIED',
        details: { serialNumber, valid, errors },
        ipAddress: req.headers['x-forwarded-for'] as string || 'unknown',
      },
    });

    return res.json({
      valid,
      serialNumber,
      subject: cert.subject.attributes.map((a: any) => `${a.shortName}=${a.value}`).join(', '),
      issuer: cert.issuer.attributes.map((a: any) => `${a.shortName}=${a.value}`).join(', '),
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
      errors: valid ? undefined : errors,
    });
  } catch (error) {
    console.error('Certificate verify error:', error);
    return res.status(500).json({ error: 'Certificate verification failed' });
  }
}
