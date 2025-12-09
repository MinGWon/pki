import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import forge from 'node-forge';
import { loadCAConfig } from '@/lib/ca-store';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const caConfig = loadCAConfig();
    if (!caConfig) {
      return res.status(500).json({ error: 'CA not initialized' });
    }

    // 폐기된 인증서 목록 조회
    const revokedCerts = await prisma.revokedCertificate.findMany({
      orderBy: { revokedAt: 'desc' },
    });

    const format = req.query.format as string;

    // JSON 형식
    if (format === 'json') {
      return res.json({
        issuer: 'CN=2Check Intermediate CA, O=2Check, C=KR',
        thisUpdate: new Date().toISOString(),
        nextUpdate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        revokedCertificates: revokedCerts.map((c) => ({
          serialNumber: c.serialNumber,
          revocationDate: c.revokedAt,
          reason: c.reason || 'unspecified',
        })),
      });
    }

    // PEM/DER 형식 CRL 생성 (node-forge 사용)
    const caCert = forge.pki.certificateFromPem(caConfig.intermediateCert);
    const caKey = forge.pki.privateKeyFromPem(caConfig.intermediateKey);

    // CRL 생성
    const crl = forge.pki.createCertificateRevocationList();
    crl.issuer.attributes = caCert.subject.attributes;
    crl.thisUpdate = new Date();
    crl.nextUpdate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7일 후

    // 폐기된 인증서 추가
    revokedCerts.forEach((revoked) => {
      crl.addRevokedCertificate({
        serialNumber: revoked.serialNumber,
        revocationDate: revoked.revokedAt,
        reason: forge.pki.crl.reasonCodes[revoked.reason as keyof typeof forge.pki.crl.reasonCodes] || 0,
      });
    });

    // CRL 서명
    crl.sign(caKey, forge.md.sha256.create());

    // PEM 형식으로 변환
    const crlPem = forge.pki.crlToPem(crl);

    if (format === 'der') {
      const crlDer = forge.asn1.toDer(forge.pki.crlToAsn1(crl)).getBytes();
      res.setHeader('Content-Type', 'application/pkix-crl');
      res.setHeader('Content-Disposition', 'attachment; filename="crl.crl"');
      return res.send(Buffer.from(crlDer, 'binary'));
    }

    // 기본: PEM 형식
    res.setHeader('Content-Type', 'application/x-pem-file');
    return res.send(crlPem);
  } catch (error) {
    console.error('CRL generation error:', error);
    return res.status(500).json({ error: 'Failed to generate CRL' });
  }
}
