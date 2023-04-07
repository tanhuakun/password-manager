import { React, useContext } from "react";
import PasswordTablePage from "./PasswordTablePage";
import SetPasswordPage from "./SetPasswordPage";
import { UserMasterPasswordContext } from "App";

function PasswordMainPage() {
  const { userMasterPassword } = useContext(UserMasterPasswordContext);

  return (
    <div className="w-100 h-100 d-flex d-flex align-items-center justify-content-center">
      {userMasterPassword ? <PasswordTablePage /> : <SetPasswordPage />}
    </div>
  );
}

export default PasswordMainPage;
