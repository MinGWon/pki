import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

    console.log('[token] Request:', { grant_type, code, redirect_uri, client_id, client_secret: client_secret ? '***' : undefined });

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    if (!code || !client_id) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'code and client_id are required' });
    }

    // 1. Authorization Code 조회
    const authCode = await prisma.oAuthAuthorizationCode.findUnique({
      where: { code },
    });

    if (!authCode) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
    }

    // 2. 만료 확인
    if (authCode.expiresAt < new Date()) {
      await prisma.oAuthAuthorizationCode.delete({ where: { code } });
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
    }

    // 3. client_id 검증
    if (authCode.clientId !== client_id && authCode.clientId !== 'default') {
      return res.status(400).json({ error: 'invalid_client', error_description: 'Client ID mismatch' });
    }

    // 4. Client 조회 및 client_secret 검증 (default 클라이언트 제외)
    if (client_id !== 'default') {
      const client = await prisma.oAuthClient.findUnique({
        where: { clientId: client_id },
      });

      if (!client) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client not found' });
      }

      // Confidential client는 client_secret 필수
      if (client.clientSecret && client.clientSecret !== client_secret) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
      }
    }

    // 5. redirect_uri 검증 (postmessage 제외)
    if (redirect_uri && authCode.redirectUri !== 'postmessage' && authCode.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
    }

    // 6. PKCE code_verifier 검증 (있는 경우)
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' });
      }

      const crypto = await import('crypto');
      let computedChallenge: string;

      if (authCode.codeChallengeMethod === 'S256') {
        computedChallenge = crypto
          .createHash('sha256')
          .update(code_verifier)
          .digest('base64url');
      } else {
        computedChallenge = code_verifier;
      }

      if (computedChallenge !== authCode.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid code_verifier' });
      }
    }

    // 7. User 조회
    const user = await prisma.user.findUnique({
      where: { id: authCode.userId },
    });

    if (!user) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'User not found' });
    }

    // 8. Authorization Code 삭제 (일회용)
    await prisma.oAuthAuthorizationCode.delete({ where: { code } });

    // 9. 토큰 생성
    const accessToken = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        name: user.name,
        scope: authCode.scope,
        client_id: client_id,
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    const idToken = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        name: user.name,
        aud: client_id,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      JWT_SECRET
    );

    console.log('[token] Success for user:', user.id);

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: idToken,
      scope: authCode.scope,
    });
  } catch (error) {
    console.error('[token] Error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}
