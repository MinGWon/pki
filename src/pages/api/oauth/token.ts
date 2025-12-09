import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { hashSHA256, generateTokens } from '@/lib/crypto';
import { signJWT } from '@/lib/jwt';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    // 클라이언트 검증
    const client = await prisma.oAuthClient.findUnique({
      where: { clientId: client_id },
    });

    if (!client || client.clientSecret !== client_secret) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    // Authorization Code 검증
    const authCode = await prisma.oAuthAuthorizationCode.findUnique({
      where: { code },
    });

    if (!authCode || authCode.clientId !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    if (new Date() > authCode.expiresAt) {
      await prisma.oAuthAuthorizationCode.delete({ where: { id: authCode.id } });
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
    }

    if (authCode.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // PKCE 검증
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' });
      }
      const computedChallenge = hashSHA256(code_verifier);
      if (computedChallenge !== authCode.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }

    // 사용자 조회
    const user = await prisma.user.findUnique({ where: { id: authCode.userId } });
    if (!user) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // 토큰 생성
    const { accessToken, refreshToken } = generateTokens();
    const expiresAt = new Date(Date.now() + 3600 * 1000);

    const jwt = await signJWT({
      sub: user.id,
      email: user.email,
      name: user.name,
      scope: authCode.scope || undefined,
      client_id: client_id,
    });

    await prisma.oAuthToken.create({
      data: {
        accessToken,
        refreshToken,
        clientId: client_id,
        userId: user.id,
        scope: authCode.scope,
        expiresAt,
      },
    });

    await prisma.oAuthAuthorizationCode.delete({ where: { id: authCode.id } });

    return res.json({
      access_token: jwt,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: authCode.scope,
    });
  } catch (error) {
    console.error('Token error:', error);
    return res.status(500).json({ error: 'server_error' });
  }
}
