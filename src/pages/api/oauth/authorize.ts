import type { NextApiRequest, NextApiResponse } from 'next';
import { prisma } from '@/lib/prisma';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;

  // 필수 파라미터 검증
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).json({ 
      error: 'invalid_request', 
      error_description: 'Missing required parameters' 
    });
  }

  // 클라이언트 검증
  const client = await prisma.oAuthClient.findUnique({
    where: { clientId: client_id as string },
  });

  if (!client) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Redirect URI 검증
  const allowedUris = client.redirectUris as string[];
  if (!allowedUris.includes(redirect_uri as string)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  }

  // 인증서 선택 페이지로 리다이렉트
  const authUrl = new URL('/auth/certificate', process.env.NEXT_PUBLIC_APP_URL);
  authUrl.searchParams.set('client_id', client_id as string);
  authUrl.searchParams.set('redirect_uri', redirect_uri as string);
  authUrl.searchParams.set('scope', (scope as string) || '');
  authUrl.searchParams.set('state', (state as string) || '');
  if (code_challenge) {
    authUrl.searchParams.set('code_challenge', code_challenge as string);
    authUrl.searchParams.set('code_challenge_method', (code_challenge_method as string) || 'S256');
  }

  return res.redirect(302, authUrl.toString());
}
