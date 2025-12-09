export interface AuthMessage {
  type: 'PKI_AUTH_REQUEST' | 'PKI_AUTH_RESPONSE' | 'PKI_AUTH_CANCEL' | 'PKI_AUTH_ERROR';
  payload?: any;
  requestId?: string;
}

export interface AuthRequest {
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

export interface AuthResponse {
  code: string;
  state?: string;
}

const ALLOWED_ORIGINS = [
  'https://pki.2check.io',
  'http://localhost:3000',
];

export function isAllowedOrigin(origin: string): boolean {
  return ALLOWED_ORIGINS.includes(origin) || origin.endsWith('.2check.io');
}

export function sendMessage(target: Window, message: AuthMessage, targetOrigin: string): void {
  target.postMessage(message, targetOrigin);
}

export function createMessageHandler(
  onRequest: (data: AuthRequest, origin: string) => void,
  onCancel?: () => void
): (event: MessageEvent) => void {
  return (event: MessageEvent) => {
    if (!isAllowedOrigin(event.origin)) {
      console.warn('Message from unauthorized origin:', event.origin);
      return;
    }

    const message = event.data as AuthMessage;

    switch (message.type) {
      case 'PKI_AUTH_REQUEST':
        onRequest(message.payload, event.origin);
        break;
      case 'PKI_AUTH_CANCEL':
        onCancel?.();
        break;
    }
  };
}
