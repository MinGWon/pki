import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import forge from 'node-forge';
import { getParsedSigningCA } from '@/lib/ca-store';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { format = 'pem' } = req.query;

    // 폐지된 인증서 목록 조회
    const revokedCerts = await prisma.revokedCertificate.findMany({
      orderBy: { revokedAt: 'desc' },
    });

    // CA 인증서 및 키 가져오기
    const caInfo = getParsedSigningCA();
    if (!caInfo) {
      return res.status(500).json({ error: 'CA not initialized' });
    }

    // CRL 생성 (node-forge에서 CRL은 수동으로 생성해야 함)
    const crl: any = {
      tbsCertList: {
        version: 1,
        signature: { algorithmOid: forge.pki.oids.sha256WithRSAEncryption },
        issuer: caInfo.cert.subject.attributes,
        thisUpdate: new Date(),
        nextUpdate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7일 후
        revokedCertificates: revokedCerts.map((rc) => ({
          serialNumber: rc.serialNumber,
          revocationDate: rc.revokedAt,
        })),
      },
    };

    // CRL 서명 (간소화된 구현 - 실제로는 ASN.1 인코딩 필요)
    // node-forge에는 CRL 생성 함수가 없으므로 기본 구조만 반환
    const crlText = `-----BEGIN X509 CRL-----
Version: 2
Signature Algorithm: sha256WithRSAEncryption
Issuer: ${forge.pki.certificateToPem(caInfo.cert).split('\n')[0]}
Last Update: ${crl.tbsCertList.thisUpdate.toISOString()}
Next Update: ${crl.tbsCertList.nextUpdate.toISOString()}

Revoked Certificates:
${revokedCerts
  .map(
    (rc) =>
      `    Serial Number: ${rc.serialNumber}\n    Revocation Date: ${rc.revokedAt.toISOString()}`
  )
  .join('\n')}
-----END X509 CRL-----`;

    if (format === 'pem') {
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Content-Disposition', 'attachment; filename="crl.pem"');
      return res.send(crlText);
    } else {
      return res.json({
        version: 2,
        issuer: forge.pki.certificateToPem(caInfo.cert).split('\n')[0],
        thisUpdate: crl.tbsCertList.thisUpdate,
        nextUpdate: crl.tbsCertList.nextUpdate,
        revokedCertificates: revokedCerts,
      });
    }
  } catch (error) {
    console.error('[CRL] Error:', error);
    return res.status(500).json({ error: 'Failed to generate CRL' });
  }
}
