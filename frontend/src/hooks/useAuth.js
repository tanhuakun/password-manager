import { createContext, useContext, useState } from "react";
import { check_login } from "api/authentication";

export const AuthContext = createContext();
export const useAuth = () => {
  return useContext(AuthContext);
};

export function AuthProvider({ children }) {
  // eslint-disable-next-line
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  async function checkUserLoggedIn() {
    let res = await check_login();
    if (res.status === 401) {
      console.log("Unauthorized");
      setIsAuthenticated(false);
      return false;
    }

    if (!res || res.status !== 200) {
      throw new Error("Server error when loading authentication details");
    }

    setIsAuthenticated(true);
    return true;
  }

  const value = {
    checkUserLoggedIn,
    isAuthenticated,
    setIsAuthenticated,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
