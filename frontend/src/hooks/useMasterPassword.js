import { createContext, useContext, useState } from "react";

const MasterPasswordContext = createContext();
export const useMasterPassword = () => {
  return useContext(MasterPasswordContext);
};

export function MasterPasswordProvider({ children }) {
  const [masterPassword, setMasterPassword] = useState("");

  const value = {
    masterPassword,
    setMasterPassword,
  };

  return (
    <MasterPasswordContext.Provider value={value}>
      {children}
    </MasterPasswordContext.Provider>
  );
}
