import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { createVerify } from 'crypto';
import { safeBase64Decode, normalizeBase64 } from '@/lib/base64';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { challenge, signature, certificateSerialNumber } = req.body;

    console.log('[VERIFY DEBUG] challenge:', challenge);
    console.log('[VERIFY DEBUG] signature 길이:', signature?.length);
    console.log('[VERIFY DEBUG] certificateSerialNumber:', certificateSerialNumber);

    if (!challenge || !signature || !certificateSerialNumber) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 챌린지 확인
    const challengeRecord = await prisma.challenge.findUnique({
      where: { challenge },
    });

    if (!challengeRecord) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    if (new Date() > challengeRecord.expiresAt) {
      await prisma.challenge.delete({ where: { id: challengeRecord.id } });
      return res.status(400).json({ error: 'Challenge expired' });
    }

    // Agent가 보낸 실제 serialNumber로 DB 조회
    const certificate = await prisma.certificate.findUnique({
      where: { serialNumber: certificateSerialNumber },  // ← 실제 serialNumber
      include: { user: true },
    });

    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    if (certificate.status !== 'ACTIVE') {
      return res.status(400).json({ error: `Certificate is ${certificate.status}` });
    }

    // 서명 검증
    console.log('[VERIFY DEBUG] 서명 검증 시작');
    console.log('[VERIFY DEBUG] publicKey 길이:', certificate.publicKey?.length);

    let signatureBuffer: Buffer;
    try {
      // Base64 정규화 후 디코딩
      signatureBuffer = safeBase64Decode(signature);
      console.log('[VERIFY DEBUG] signature 디코딩 성공, 길이:', signatureBuffer.length);
    } catch (e) {
      console.error('[VERIFY DEBUG] signature 디코딩 실패:', e);
      return res.status(400).json({ error: 'Invalid signature format' });
    }

    let challengeBuffer: Buffer;
    try {
      // 챌린지도 Base64일 수 있음
      if (challenge.match(/^[A-Za-z0-9+/=_-]+$/)) {
        challengeBuffer = safeBase64Decode(challenge);
      } else {
        challengeBuffer = Buffer.from(challenge, 'utf-8');
      }
      console.log('[VERIFY DEBUG] challenge 버퍼 길이:', challengeBuffer.length);
    } catch (e) {
      challengeBuffer = Buffer.from(challenge, 'utf-8');
    }

    const verifier = createVerify('RSA-SHA256');
    verifier.update(challengeBuffer);

    let isValid: boolean;
    try {
      isValid = verifier.verify(certificate.publicKey, signatureBuffer);
      console.log('[VERIFY DEBUG] 검증 결과:', isValid);
    } catch (e) {
      console.error('[VERIFY DEBUG] 검증 오류:', e);
      return res.status(400).json({ error: 'Signature verification failed' });
    }

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // 챌린지 삭제 (일회용)
    await prisma.challenge.delete({ where: { id: challengeRecord.id } });

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'SIGNATURE_VERIFIED',
        userId: certificate.userId,
        details: {
          certificateSerialNumber,
        },
        ipAddress: req.headers['x-forwarded-for'] as string || 'unknown',
      },
    });

    return res.json({
      success: true,
      user: {
        id: certificate.user.id,
        email: certificate.user.email,
        name: certificate.user.name,
      },
    });
  } catch (error) {
    console.error('Signature verify error:', error);
    return res.status(500).json({ error: 'Verification failed' });
  }
}
