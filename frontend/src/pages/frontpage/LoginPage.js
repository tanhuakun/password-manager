import React, { useState, useLayoutEffect } from "react";
import { useGoogleLogin } from "@react-oauth/google";
import {
  post_login,
  post_google_login,
  check_login,
} from "api/authentication.js";
import { Link } from "react-router-dom";
import Toast from "react-bootstrap/Toast";
import ToastContainer from "react-bootstrap/ToastContainer";
import Spinner from "react-bootstrap/Spinner";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";

function LoginPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [isInvalidCredentials, setIsInvalidCredentials] = useState(false);

  const [errorMessage, setErrorMessage] = useState({
    title: "",
    body: "",
  });

  const [formData, setFormData] = useState({
    username: "",
    password: "",
  });

  const [showErrorToast, setShowErrorToast] = useState(false);

  useLayoutEffect(() => {
    async function check() {
      let res = await check_login();
      if (!res) {
        return;
      }

      if (res.status === 401) {
        console.log("Unauthorized");
      }

      // TODO redirect
      console.log(res);
    }
    check();
  }, []);

  const toggleErrorToast = () => setShowErrorToast(!showErrorToast);

  function showToastMessage(title, body) {
    setErrorMessage({
      title: title,
      body: body,
    });
    setShowErrorToast(true);
  }

  function handleChange(e) {
    setIsInvalidCredentials(false);
    const key = e.target.name;
    const value = e.target.value;
    setFormData({ ...formData, [key]: value });
  }

  const googleLogin = useGoogleLogin({
    onSuccess: async (credentialResponse) => {
      console.log(credentialResponse);
      let res = await post_google_login({
        access_token: credentialResponse.access_token,
      });
      if (!res) {
        showToastMessage(
          "Server Error",
          "Something went wrong with the server! Please try again later"
        );
        return;
      }

      // TODO happy path
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
    console.log(formData);
    setIsLoading(true);
    const res = await post_login({
      username: formData.username,
      password: formData.password,
    });
    setIsLoading(false);

    if (!res) {
      showToastMessage(
        "Server Error",
        "Something went wrong with the server! Please try again later"
      );
      return;
    }

    if (res.status === 401) {
      setIsInvalidCredentials(true);
      return;
    }

    // TODO happy path
  }

  return (
    <div className="d-flex h-100 p-3 d-flex align-items-center justify-content-center">
      <ToastContainer className="p-3" position="top-center">
        <Toast show={showErrorToast} onClose={toggleErrorToast}>
          <Toast.Header>
            <strong className="me-auto">{errorMessage.title}</strong>
          </Toast.Header>
          <Toast.Body>{errorMessage.body}</Toast.Body>
        </Toast>
      </ToastContainer>
      <div className="w-50 h-75">
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
            <Form.Label>Password</Form.Label>
            <Form.Control
              name="password"
              type="password"
              placeholder="Password"
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
      </div>
    </div>
  );
}

export default LoginPage;
