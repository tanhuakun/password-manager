import "./App.css";
import LoginPage from "./pages/frontpage/LoginPage";
import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import RegisterPage from "./pages/frontpage/RegisterPage";
import PasswordTable from "./pages/main/passwords/PasswordTablePage";
import CustomNavbar from "pages/main/CustomNavbar";
import TwoFactorAuthPage from "pages/main/twofactorauth/TwoFactorAuthPage";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/" element={<CustomNavbar />}>
          <Route path="/home" element={<PasswordTable />} />
          <Route path="/2fa" element={<TwoFactorAuthPage />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
