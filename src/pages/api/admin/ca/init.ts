import type { NextApiRequest, NextApiResponse } from 'next';
import { generateRootCA, generateIntermediateCA } from '@/lib/ca';
import { saveCAConfig, isCAInitialized } from '@/lib/ca-store';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 개발 환경에서는 시크릿 체크 완화
  const adminSecret = req.headers['x-admin-secret'];
  const isDev = process.env.NODE_ENV === 'development';
  
  if (!isDev && adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (isCAInitialized()) {
    return res.status(400).json({ error: 'CA already initialized', message: 'CA가 이미 초기화되었습니다.' });
  }

  try {
    const rootCA = generateRootCA({
      commonName: '2Check Root CA',
      organization: '2Check',
      country: 'KR',
    }, 10);

    const intermediateCA = generateIntermediateCA({
      commonName: '2Check Intermediate CA',
      organization: '2Check',
      country: 'KR',
    }, rootCA.certificatePem, rootCA.privateKeyPem, 5);

    saveCAConfig({
      rootCert: rootCA.certificatePem,
      rootKey: rootCA.privateKeyPem,
      intermediateCert: intermediateCA.certificatePem,
      intermediateKey: intermediateCA.privateKeyPem,
    });

    return res.json({
      success: true,
      message: 'CA 초기화 완료',
      rootCA: {
        serialNumber: rootCA.serialNumber,
        subjectDN: rootCA.subjectDN,
        notAfter: rootCA.notAfter,
      },
      intermediateCA: {
        serialNumber: intermediateCA.serialNumber,
        subjectDN: intermediateCA.subjectDN,
        notAfter: intermediateCA.notAfter,
      },
    });
  } catch (error) {
    console.error('CA initialization error:', error);
    return res.status(500).json({ error: 'Failed to initialize CA' });
  }
}
