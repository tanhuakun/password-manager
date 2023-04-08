import "./App.css";
import LoginPage from "./pages/frontpage/LoginPage";
import { React, useState, createContext, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import RegisterPage from "./pages/frontpage/RegisterPage";
import PasswordMainPage from "./pages/main/passwords/PasswordMainPage";
import CustomNavbar from "pages/main/CustomNavbar";
import TwoFactorAuthPage from "pages/main/twofactorauth/TwoFactorAuthPage";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Verify2FAPage from "pages/frontpage/Verify2FAPage";
import RequireAuthLayout from "components/RequireAuthLayout";
import { useAuth } from "hooks/useAuth";
import Spinner from "react-bootstrap/Spinner";

export const UserMasterPasswordContext = createContext(null);

function App() {
  const [userMasterPassword, setUserMasterPassword] = useState("");
  const { checkUserLoggedIn } = useAuth();
  const [isLoadingData, setIsLoadingData] = useState(true);
  const [isAppError, setIsAppError] = useState(false);

  async function loadData() {
    console.log("Loading data");
    let authPromise = checkUserLoggedIn();

    try {
      await authPromise;
    } catch (error) {
      console.error(error);
      setIsAppError(true);
      return;
    }
    console.log("Data loaded");
    setIsLoadingData(false);
  }

  useEffect(() => {
    loadData();
    // eslint-disable-next-line
  }, []);

  return (
    <Router>
      <UserMasterPasswordContext.Provider
        value={{ userMasterPassword, setUserMasterPassword }}
      >
        {isAppError ? (
          <div className="d-flex h-100 p-3 flex-column align-items-center justify-content-center text-danger">
            <div>Error loading resources, please try again later!</div>
          </div>
        ) : isLoadingData ? (
          <div className="d-flex h-100 p-3 flex-column align-items-center justify-content-center">
            <div>Loading...</div>
            <Spinner animation="grow" />
          </div>
        ) : (
          <Routes>
            <Route path="/" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/verify_2fa" element={<Verify2FAPage />} />
            <Route path="/" element={<RequireAuthLayout />}>
              <Route path="/" element={<CustomNavbar />}>
                <Route path="/home" element={<PasswordMainPage />} />
                <Route path="/2fa" element={<TwoFactorAuthPage />} />
              </Route>
            </Route>
          </Routes>
        )}
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
