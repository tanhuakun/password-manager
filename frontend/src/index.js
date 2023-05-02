import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import reportWebVitals from "./reportWebVitals";
import "bootstrap/dist/css/bootstrap.min.css";
import { GoogleOAuthProvider } from "@react-oauth/google";
import { AuthProvider } from "hooks/useAuth";
import { MasterPasswordProvider } from "hooks/useMasterPassword";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <GoogleOAuthProvider clientId={window._env_.GOOGLE_CLIENT_ID}>
    <AuthProvider>
      <MasterPasswordProvider>
        <React.StrictMode>
          <App />
        </React.StrictMode>
      </MasterPasswordProvider>
    </AuthProvider>
  </GoogleOAuthProvider>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
