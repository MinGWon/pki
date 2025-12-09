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

    console.log('[verify-and-login] Request data:', {
      challenge: challenge?.substring(0, 20) + '...',
      signature: signature?.substring(0, 20) + '...',
      certificateSerialNumber,
      clientId,
    });

    if (!challenge || !signature || !certificateSerialNumber) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 1. 인증서 조회 (User 정보 포함)
    const certificate = await prisma.certificate.findUnique({
      where: { serialNumber: certificateSerialNumber },
      include: { user: true },
    });

    if (!certificate) {
      console.error('[verify-and-login] Certificate not found:', certificateSerialNumber);
      return res.status(404).json({ error: 'Certificate not found' });
    }

    console.log('[verify-and-login] Certificate found:', {
      serialNumber: certificate.serialNumber,
      userId: certificate.userId,
      subjectDN: certificate.subjectDN,
    });

    // 2. 서명 검증
    try {
      // publicKey 형식 확인 및 변환
      let publicKeyPem = certificate.publicKey;
      
      // PEM 헤더/푸터가 없으면 추가
      if (!publicKeyPem.includes('-----BEGIN')) {
        publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyPem}\n-----END PUBLIC KEY-----`;
      }

      console.log('[verify-and-login] Public key format:', {
        hasHeader: publicKeyPem.includes('-----BEGIN'),
        length: publicKeyPem.length,
      });

      // 서명 검증 (여러 해시 알고리즘 시도)
      const algorithms = ['SHA256', 'SHA1', 'RSA-SHA256'];
      let isValid = false;
      let usedAlgorithm = '';

      for (const algorithm of algorithms) {
        try {
          const verifier = crypto.createVerify(algorithm);
          verifier.update(challenge);
          
          // Base64 디코딩된 서명으로 검증
          const signatureBuffer = Buffer.from(signature, 'base64');
          isValid = verifier.verify(publicKeyPem, signatureBuffer);
          
          if (isValid) {
            usedAlgorithm = algorithm;
            console.log(`[verify-and-login] Signature verified with ${algorithm}`);
            break;
          }
        } catch (err) {
          console.log(`[verify-and-login] ${algorithm} verification failed:`, err);
          continue;
        }
      }

      if (!isValid) {
        console.error('[verify-and-login] Signature verification failed with all algorithms');
        console.error('[verify-and-login] Challenge length:', challenge.length);
        console.error('[verify-and-login] Signature length:', signature.length);
        return res.status(401).json({ 
          error: 'Invalid signature',
          details: 'Signature verification failed with all supported algorithms'
        });
      }

      console.log('[verify-and-login] Signature verified successfully with:', usedAlgorithm);

    } catch (verifyError) {
      console.error('[verify-and-login] Signature verification error:', verifyError);
      return res.status(401).json({ error: 'Invalid signature format' });
    }

    // 3. 사용자는 이미 인증서와 연결되어 있음
    const user = certificate.user;

    // 4. Authorization Code 생성
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10분

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

    console.log('[verify-and-login] Login successful for user:', user.id);

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
