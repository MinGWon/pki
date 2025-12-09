import { randomBytes, createHash, createVerify } from 'crypto';

export function generateChallenge(): string {
  return randomBytes(32).toString('base64url');
}

export function hashSHA256(data: string): string {
  return createHash('sha256').update(data).digest('base64url');
}

export function verifySignature(
  publicKeyPem: string,
  data: string,
  signature: string,
  algorithm: string = 'RSA-SHA256'
): boolean {
  try {
    const verify = createVerify(algorithm);
    verify.update(data);
    verify.end();
    return verify.verify(publicKeyPem, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

export function generateAuthorizationCode(): string {
  return randomBytes(32).toString('base64url');
}

export function generateTokens() {
  return {
    accessToken: randomBytes(32).toString('base64url'),
    refreshToken: randomBytes(32).toString('base64url'),
  };
}
