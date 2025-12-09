import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import crypto from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // CORS 헤더 설정
  res.setHeader('Access-Control-Allow-Origin', 'https://samsquare.2check.io');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { 
      challenge, 
      signature, 
      certificateSerialNumber,
      clientId,
      redirectUri,
      scope,
      state,
    } = req.body;

    if (!challenge || !signature || !certificateSerialNumber) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 1. 인증서 조회 (User 정보 포함)
    const certificate = await prisma.certificate.findUnique({
      where: { serialNumber: certificateSerialNumber },
      include: { user: true },
    });

    if (!certificate) {
      return res.status(404).json({ error: 'Certificate not found' });
    }

    // 2. 서명 검증 (기존 /api/auth/signature/verify 로직과 동일)
    const signatureHash = crypto
      .createHash('sha256')
      .update(signature)
      .digest('hex');

    const storedSignature = await prisma.challenge.findFirst({
      where: {
        challenge: signatureHash,
        expiresAt: { gt: new Date() },
      },
    });

    if (!storedSignature) {
      // 직접 서명 검증 (fallback)
      try {
        const verifier = crypto.createVerify('SHA256');
        verifier.update(challenge);
        const isValid = verifier.verify(
          certificate.publicKey,
          Buffer.from(signature, 'base64')
        );

        if (!isValid) {
          return res.status(401).json({ error: 'Invalid signature' });
        }
      } catch (err) {
        console.error('Signature verification error:', err);
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    // 3. 사용자 정보
    const user = certificate.user;

    // 4. Authorization Code 생성
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await prisma.oAuthAuthorizationCode.create({
      data: {
        code,
        clientId: clientId || 'default',
        userId: user.id,
        redirectUri: redirectUri || 'https://samsquare.2check.io',
        scope: scope || 'openid profile email',
        expiresAt,
      },
    });

    // 5. 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'PKI_LOGIN',
        userId: user.id,
        clientId: clientId || 'default',
        details: {
          certificateSerialNumber,
          clientId: clientId || 'default',
        },
      },
    });

    // 6. Challenge 삭제 (재사용 방지)
    if (storedSignature) {
      await prisma.challenge.delete({ where: { id: storedSignature.id } });
    }

    return res.json({
      success: true,
      code,
      state: state || null,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('[verify-and-login] Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
