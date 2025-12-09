import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { userId, clientId, redirectUri, scope, codeChallenge, codeChallengeMethod } = req.body;

    console.log('[AUTH CODE DEBUG] 요청 데이터:', {
      userId,
      clientId,
      redirectUri,
      scope,
      codeChallenge: codeChallenge ? '있음' : '없음',
      codeChallengeMethod,
    });

    // 필수 필드 검증
    if (!userId) {
      console.log('[AUTH CODE DEBUG] userId 누락');
      return res.status(400).json({ error: 'userId is required' });
    }

    if (!clientId) {
      console.log('[AUTH CODE DEBUG] clientId 누락');
      return res.status(400).json({ error: 'clientId is required' });
    }

    if (!redirectUri) {
      console.log('[AUTH CODE DEBUG] redirectUri 누락');
      return res.status(400).json({ error: 'redirectUri is required' });
    }

    // 클라이언트 검증
    console.log('[AUTH CODE DEBUG] 클라이언트 검증 중...');
    const client = await prisma.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!client) {
      console.log('[AUTH CODE DEBUG] 클라이언트 없음:', clientId);
      return res.status(400).json({ error: 'Invalid client_id' });
    }

    console.log('[AUTH CODE DEBUG] 클라이언트 확인:', client.name);

    // Redirect URI 검증
    const allowedUris = client.redirectUris as string[];
    console.log('[AUTH CODE DEBUG] 허용된 URI:', allowedUris);
    console.log('[AUTH CODE DEBUG] 요청된 URI:', redirectUri);

    if (!allowedUris.includes(redirectUri)) {
      console.log('[AUTH CODE DEBUG] Redirect URI 불일치');
      return res.status(400).json({ error: 'Invalid redirect_uri' });
    }

    // 사용자 확인
    console.log('[AUTH CODE DEBUG] 사용자 확인 중...');
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      console.log('[AUTH CODE DEBUG] 사용자 없음:', userId);
      return res.status(400).json({ error: 'Invalid user' });
    }

    console.log('[AUTH CODE DEBUG] 사용자 확인:', user.email);

    // Authorization Code 생성
    const code = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10분

    console.log('[AUTH CODE DEBUG] 코드 생성:', code.substring(0, 16) + '...');

    // DB에 저장
    await prisma.oAuthAuthorizationCode.create({
      data: {
        code,
        clientId,
        userId,
        redirectUri,
        scope: scope || null,
        codeChallenge: codeChallenge || null,
        codeChallengeMethod: codeChallengeMethod || null,
        expiresAt,
      },
    });

    console.log('[AUTH CODE DEBUG] 코드 저장 완료');

    // 감사 로그
    await prisma.auditLog.create({
      data: {
        action: 'AUTHORIZATION_CODE_CREATED',
        userId,
        clientId,
        details: { redirectUri },
      },
    });

    return res.json({ code });
  } catch (error) {
    console.error('[AUTH CODE ERROR]', error);
    return res.status(500).json({
      error: 'Failed to create authorization code',
      detail: error instanceof Error ? error.message : String(error),
    });
  }
}
