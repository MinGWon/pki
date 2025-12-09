import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'https://pki.2check.io';

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/api/oauth/authorize`,
    token_endpoint: `${baseUrl}/api/oauth/token`,
    revocation_endpoint: `${baseUrl}/api/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/api/oauth/introspect`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: ['openid', 'profile', 'email'],
  });
}
