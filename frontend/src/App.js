import "./App.css";
import LoginPage from "./pages/frontpage/LoginPage";
import { React, useState, createContext } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import RegisterPage from "./pages/frontpage/RegisterPage";
import PasswordMainPage from "./pages/main/passwords/PasswordMainPage";
import CustomNavbar from "pages/main/CustomNavbar";
import TwoFactorAuthPage from "pages/main/twofactorauth/TwoFactorAuthPage";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Verify2FAPage from "pages/frontpage/Verify2FAPage";

export const UserMasterPasswordContext = createContext(null);

function App() {
  const [userMasterPassword, setUserMasterPassword] = useState("");

  return (
    <Router>
      <UserMasterPasswordContext.Provider
        value={{ userMasterPassword, setUserMasterPassword }}
      >
        <Routes>
          <Route
            path="/"
            element={
              <LoginPage setUserMasterPassword={setUserMasterPassword} />
            }
          />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/verify_2fa" element={<Verify2FAPage />} />
          <Route path="/" element={<CustomNavbar />}>
            <Route
              path="/home"
              element={
                <PasswordMainPage
                  masterPassword={userMasterPassword}
                  setMasterPassword={setUserMasterPassword}
                />
              }
            />
            <Route path="/2fa" element={<TwoFactorAuthPage />} />
          </Route>
        </Routes>
      </UserMasterPasswordContext.Provider>
      <ToastContainer
        position="top-center"
        autoClose={10000}
        hideProgressBar
        closeOnClick
      />
    </Router>
  );
}

export default App;
