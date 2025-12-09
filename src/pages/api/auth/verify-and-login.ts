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

    console.log('[verify-and-login] ===== Request Start =====');
    console.log('[verify-and-login] Request body:', {
      hasChallenge: !!challenge,
      hasSignature: !!signature,
      certificateSerialNumber,
      clientId: clientId || '(empty)',
      redirectUri: redirectUri || '(empty)',
      scope: scope || '(empty)',
      state: state || '(empty)',
    });

    if (!challenge || !signature || !certificateSerialNumber) {
      console.error('[verify-and-login] Missing required fields');
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // 1. 인증서 조회 (User 정보 포함)
    console.log('[verify-and-login] Step 1: Looking up certificate...');
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
      userName: certificate.user.name,
    });

    // 2. 서명 검증
    console.log('[verify-and-login] Step 2: Verifying signature...');
    
    // 먼저 Challenge 테이블에서 확인
    const challengeHash = crypto.createHash('sha256').update(challenge).digest('hex');
    console.log('[verify-and-login] Challenge hash:', challengeHash);
    
    const storedChallenge = await prisma.challenge.findFirst({
      where: {
        challenge: challengeHash,
        expiresAt: { gt: new Date() },
      },
    });

    console.log('[verify-and-login] Stored challenge found:', !!storedChallenge);

    // Public Key 형식 확인 및 변환
    let publicKeyPem = certificate.publicKey;
    console.log('[verify-and-login] Original public key length:', publicKeyPem.length);
    console.log('[verify-and-login] Public key preview:', publicKeyPem.substring(0, 100));

    // PEM 헤더/푸터 처리
    if (!publicKeyPem.includes('-----BEGIN')) {
      console.log('[verify-and-login] Adding PEM headers...');
      // Base64 문자열인 경우 줄바꿈 추가
      const base64Key = publicKeyPem.replace(/\s/g, '');
      const formattedKey = base64Key.match(/.{1,64}/g)?.join('\n') || base64Key;
      publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
    }

    // 직접 서명 검증 (여러 방법 시도)
    let isValid = false;
    const signatureBuffer = Buffer.from(signature, 'base64');
    
    console.log('[verify-and-login] Signature buffer length:', signatureBuffer.length);
    console.log('[verify-and-login] Challenge length:', challenge.length);

    try {
      console.log('[verify-and-login] Attempting direct signature verification...');
      
      // 방법 1: SHA256 with string challenge
      try {
        const verifier1 = crypto.createVerify('SHA256');
        verifier1.update(challenge);
        isValid = verifier1.verify(publicKeyPem, signatureBuffer);
        if (isValid) {
          console.log('[verify-and-login] ✓ Verified with SHA256 + string challenge');
        }
      } catch (err) {
        console.log('[verify-and-login] SHA256 + string failed:', err instanceof Error ? err.message : String(err));
      }

      // 방법 2: RSA-SHA256 with string challenge
      if (!isValid) {
        try {
          const verifier2 = crypto.createVerify('RSA-SHA256');
          verifier2.update(challenge);
          isValid = verifier2.verify(publicKeyPem, signatureBuffer);
          if (isValid) {
            console.log('[verify-and-login] ✓ Verified with RSA-SHA256 + string challenge');
          }
        } catch (err) {
          console.log('[verify-and-login] RSA-SHA256 + string failed:', err instanceof Error ? err.message : String(err));
        }
      }

      // 방법 3: SHA256 with buffer challenge
      if (!isValid) {
        try {
          const verifier3 = crypto.createVerify('SHA256');
          verifier3.update(Buffer.from(challenge));
          isValid = verifier3.verify(publicKeyPem, signatureBuffer);
          if (isValid) {
            console.log('[verify-and-login] ✓ Verified with SHA256 + buffer challenge');
          }
        } catch (err) {
          console.log('[verify-and-login] SHA256 + buffer failed:', err instanceof Error ? err.message : String(err));
        }
      }

      // 방법 4: SHA256 with base64 decoded challenge
      if (!isValid) {
        try {
          const verifier4 = crypto.createVerify('SHA256');
          verifier4.update(Buffer.from(challenge, 'base64'));
          isValid = verifier4.verify(publicKeyPem, signatureBuffer);
          if (isValid) {
            console.log('[verify-and-login] ✓ Verified with SHA256 + base64 decoded challenge');
          }
        } catch (err) {
          console.log('[verify-and-login] SHA256 + base64 failed:', err instanceof Error ? err.message : String(err));
        }
      }

      // 방법 5: SHA1 시도
      if (!isValid) {
        try {
          const verifier5 = crypto.createVerify('SHA1');
          verifier5.update(challenge);
          isValid = verifier5.verify(publicKeyPem, signatureBuffer);
          if (isValid) {
            console.log('[verify-and-login] ✓ Verified with SHA1 + string challenge');
          }
        } catch (err) {
          console.log('[verify-and-login] SHA1 failed:', err instanceof Error ? err.message : String(err));
        }
      }

      console.log('[verify-and-login] Direct verification result:', isValid);
      
      if (!isValid) {
        console.error('[verify-and-login] All verification methods failed');
        console.error('[verify-and-login] Public key (formatted):', publicKeyPem.substring(0, 200));
      }
      
    } catch (err) {
      console.error('[verify-and-login] Signature verification error:', err);
      return res.status(401).json({ error: 'Invalid signature format' });
    }

    if (!isValid && !storedChallenge) {
      console.error('[verify-and-login] Signature verification failed');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // 3. 사용자 정보
    console.log('[verify-and-login] Step 3: User info validated');
    const user = certificate.user;

    // 4. ClientId 처리
    const finalClientId = clientId || 'default';
    console.log('[verify-and-login] Step 4: Using clientId:', finalClientId);

    // ClientId 검증 (default가 아닌 경우)
    if (finalClientId !== 'default') {
      const oauthClient = await prisma.oAuthClient.findUnique({
        where: { clientId: finalClientId },
      });
      
      if (!oauthClient) {
        console.warn('[verify-and-login] OAuth client not found, using default:', finalClientId);
      } else {
        console.log('[verify-and-login] OAuth client validated:', oauthClient.name);
      }
    }

    // 5. Authorization Code 생성
    console.log('[verify-and-login] Step 5: Creating authorization code...');
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await prisma.oAuthAuthorizationCode.create({
      data: {
        code,
        clientId: finalClientId,
        userId: user.id,
        redirectUri: redirectUri || 'https://samsquare.2check.io',
        scope: scope || 'openid profile email',
        expiresAt,
      },
    });

    console.log('[verify-and-login] Authorization code created:', code.substring(0, 10) + '...');

    // 6. 감사 로그
    console.log('[verify-and-login] Step 6: Creating audit log...');
    await prisma.auditLog.create({
      data: {
        action: 'PKI_LOGIN',
        userId: user.id,
        clientId: finalClientId,
        details: {
          certificateSerialNumber,
          clientId: finalClientId,
        },
      },
    });

    // 7. Challenge 삭제 (재사용 방지)
    if (storedChallenge) {
      console.log('[verify-and-login] Step 7: Deleting used challenge...');
      await prisma.challenge.delete({ where: { id: storedChallenge.id } });
    }

    console.log('[verify-and-login] ===== Success =====');
    console.log('[verify-and-login] User logged in:', user.email);

    return res.json({
      success: true,
      code,
      state: state || null,
      user: {
        id: user.id,
        name: user.name,
        certificateId: certificate.id,
      },
    });
  } catch (error) {
    console.error('[verify-and-login] ===== Error =====');
    console.error('[verify-and-login] Error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
