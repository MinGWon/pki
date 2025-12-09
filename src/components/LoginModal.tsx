import CertificateSelectModal from './CertificateSelectModal';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (user: { id: string; name: string; email: string }) => void;
}

export default function LoginModal({ isOpen, onClose, onSuccess }: LoginModalProps) {
  function handleSelect(result: { user?: any }) {
    if (result.user && onSuccess) {
      onSuccess(result.user);
    }
    onClose();
  }

  return (
    <CertificateSelectModal
      isOpen={isOpen}
      onClose={onClose}
      onSelect={handleSelect}
      title="인증서 로그인"
      description="로그인에 사용할 인증서를 선택하세요."
    />
  );
}
