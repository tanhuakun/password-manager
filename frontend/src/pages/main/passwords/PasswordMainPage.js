import { React } from "react";
import PasswordTablePage from "./PasswordTablePage";
import SetPasswordPage from "./SetPasswordPage";
import { useMasterPassword } from "hooks/useMasterPassword";

function PasswordMainPage() {
  const { masterPassword } = useMasterPassword();

  return (
    <div className="w-100 h-100 d-flex d-flex align-items-center justify-content-center">
      {masterPassword ? <PasswordTablePage /> : <SetPasswordPage />}
    </div>
  );
}

export default PasswordMainPage;
