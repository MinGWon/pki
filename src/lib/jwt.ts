import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export interface JWTPayload {
  sub: string;
  email?: string;
  name?: string;
  scope?: string;
  client_id?: string;
  iat?: number;
  exp?: number;
}

export async function verifyJWT(token: string): Promise<JWTPayload | null> {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as JWTPayload;
    console.log('[jwt] Verified successfully, sub:', payload.sub);
    return payload;
  } catch (error) {
    console.error('[jwt] Verification failed:', error instanceof Error ? error.message : error);
    return null;
  }
}

export function signJWT(payload: object, expiresIn: string = '1h'): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
