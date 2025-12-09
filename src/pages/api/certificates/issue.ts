import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { hashPhoneNumber } from '@/lib/hash';
import { issueCertificate } from '@/lib/ca';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  console.log('[issue] ========== 인증서 발급 요청 ==========');
  console.log('[issue] req.body:', JSON.stringify(req.body, null, 2));

  try {
    const { userId, commonName, name, phone, email, password, validityYears = 1 } = req.body;

    const userName = commonName || name;

    // 유효성 검사
    if (!userName) {
      return res.status(400).json({ error: '이름은 필수입니다.' });
    }
    if (!phone) {
      return res.status(400).json({ error: '전화번호는 필수입니다.' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: '비밀번호는 8자 이상이어야 합니다.' });
    }

    // userId 생성 (전달받은 값 또는 전화번호 해시)
    const finalUserId = userId || hashPhoneNumber(phone);
    console.log('[issue] userId:', finalUserId);

    // 사용자 조회/생성
    let user = await prisma.user.findUnique({ where: { id: finalUserId } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          id: finalUserId,
          name: userName,
          phone,
          email: email || null,
        },
      });
      console.log('[issue] 새 사용자 생성:', user.id);
    } else {
      if (user.name !== userName) {
        user = await prisma.user.update({
          where: { id: finalUserId },
          data: { name: userName },
        });
      }
      console.log('[issue] 기존 사용자:', user.id);
    }

    // 인증서 발급
    console.log('[issue] 인증서 생성 중...');
    const certResult = await issueCertificate({
      commonName: userName,
      email: email || undefined,
      userId: finalUserId,
      password,
      validityYears,
    });

    console.log('[issue] 인증서 생성 완료, serialNumber:', certResult.serialNumber);

    // DB에 인증서 정보 저장
    const certificate = await prisma.certificate.create({
      data: {
        serialNumber: certResult.serialNumber,
        subjectDN: certResult.subjectDN,
        issuerDN: certResult.issuerDN,
        notBefore: new Date(certResult.notBefore),
        notAfter: new Date(certResult.notAfter),
        publicKey: certResult.publicKeyPem,
        status: 'ACTIVE',
        userId: user.id,
      },
    });

    console.log('[issue] DB 저장 완료, id:', certificate.id);

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'CERTIFICATE_ISSUED',
        userId: user.id,
        details: {
          serialNumber: certResult.serialNumber,
          subjectDN: certResult.subjectDN,
        },
      },
    });

    return res.status(200).json({
      success: true,
      certificate: {
        id: certificate.id,
        serialNumber: certificate.serialNumber,
        subjectDN: `CN=${userName}, O=2Check, C=KR`,  // 원본 한글 이름
        issuerDN: certificate.issuerDN,
        notBefore: certificate.notBefore.toISOString(),
        notAfter: certificate.notAfter.toISOString(),
      },
      p12: certResult.p12Base64,
      displayName: userName,  // 표시용 원본 한글 이름
    });

  } catch (error) {
    console.error('[issue] ERROR:', error);
    return res.status(500).json({ 
      error: '인증서 발급 실패',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
}
