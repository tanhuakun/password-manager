import React, { useState, useEffect } from "react";
import { useGoogleLogin } from "@react-oauth/google";
import { post_login, post_google_login } from "api/authentication.js";
import { Link, useNavigate } from "react-router-dom";
import Spinner from "react-bootstrap/Spinner";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import { toast } from "react-toastify";
import { clientPasswordHash } from "utils/crypto";
import { useAuth } from "hooks/useAuth";
import { useMasterPassword } from "hooks/useMasterPassword";
import { Github } from "react-bootstrap-icons";

function LoginPage() {
  const { isAuthenticated, setIsAuthenticated } = useAuth();
  const { setMasterPassword } = useMasterPassword();
  const NEXT_DASHBOARD = "Dashboard";
  const NEXT_2FA = "2FA";
  const [isLoading, setIsLoading] = useState(false);
  const [isInvalidCredentials, setIsInvalidCredentials] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
  });
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate("/home");
    }
    // eslint-disable-next-line
  }, []);

  function handleChange(e) {
    setIsInvalidCredentials(false);
    const key = e.target.name;
    const value = e.target.value;
    setFormData({ ...formData, [key]: value });
  }

  function handle_login_response(res) {
    setIsAuthenticated(true);
    if (res.data.next === NEXT_DASHBOARD) {
      navigate("/home");
    } else if (res.data.next === NEXT_2FA) {
      navigate("/verify_2fa");
    } else {
      toast.error("Something went wrong!");
    }
  }

  const googleLogin = useGoogleLogin({
    onSuccess: async (credentialResponse) => {
      console.log(credentialResponse);
      let res = await post_google_login({
        access_token: credentialResponse.access_token,
      });
      if (!res || res.status !== 200) {
        toast.error("Server error!");
        return;
      }

      handle_login_response(res);
    },
    onError: () => {
      console.log("Login Failed");
    },
    flow: "implicit",
  });

  async function login(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }
    setIsLoading(true);
    const submittedPassword = formData.password;
    const submittedPasswordHash = await clientPasswordHash(submittedPassword);
    const res = await post_login({
      username: formData.username,
      password: submittedPasswordHash,
    });
    setIsLoading(false);

    if (res.status === 401) {
      setIsInvalidCredentials(true);
      return;
    }

    if (!res || res.status !== 200) {
      toast.error("Server error!");
      return;
    }

    setMasterPassword(submittedPassword);
    setFormData({
      username: "",
      password: "",
    });
    handle_login_response(res);
  }

  return (
    <div className="d-flex h-100 p-3 d-flex align-items-center justify-content-center">
      <div className="frontpage_box h-75">
        <div className="text-center mb-4">
          <h3 className="display-3">Password Manager</h3>
        </div>
        <Form className="w-100" onSubmit={login}>
          <Form.Group className="mb-3" controlId="formGroupUsername">
            <Form.Label>Username</Form.Label>
            <Form.Control
              name="username"
              type="text"
              placeholder="Enter username"
              required
              onChange={handleChange}
              isInvalid={isInvalidCredentials}
            />
            <Form.Control.Feedback type="invalid">
              Incorrect User Details!
            </Form.Control.Feedback>
          </Form.Group>
          <Form.Group className="mb-3" controlId="formGroupPassword">
            <Form.Label>Master Password</Form.Label>
            <Form.Control
              name="password"
              type="password"
              placeholder="Master Password"
              required
              onChange={handleChange}
              isInvalid={isInvalidCredentials}
            />
            <Form.Control.Feedback type="invalid">
              Incorrect User Details!
            </Form.Control.Feedback>
            <div className="d-flex flex-row justify-content-end">
              {/* 
                Will a forget password be relevant here?
                <a href="/forgot">Forgot Password</a>
              */}
            </div>
          </Form.Group>
          <Button variant="primary" type="submit" className="w-100">
            Login
          </Button>
        </Form>
        <div>
          <Button
            variant="light"
            className="border w-100 mt-3"
            onClick={() => googleLogin()}
          >
            Sign in with Google 🚀{" "}
          </Button>
        </div>
        {isLoading && (
          <div className="w-100 text-center mt-2">
            <Spinner animation="border" role="status" variant="secondary">
              <span className="visually-hidden">Loading...</span>
            </Spinner>
          </div>
        )}
        <div className="d-flex flex-row m-4 justify-content-around">
          <p>
            Don't have an account? <Link to="/register">Sign up!</Link>
          </p>
        </div>
        <div className="w-100 text-center">
          <a href="https://github.com/tanhuakun/password-manager">
            <Github size={34} style={{ cursor: "grab" }} color="black" />
          </a>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
