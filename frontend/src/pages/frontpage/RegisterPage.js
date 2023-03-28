import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { post_register } from "api/authentication.js";
import Toast from "react-bootstrap/Toast";
import ToastContainer from "react-bootstrap/ToastContainer";
import Spinner from "react-bootstrap/Spinner";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";

function RegisterPage() {
  const [doPasswordsMatch, setDoPasswordsMatch] = useState(true);
  const [isExistingUser, setIsExistingUser] = useState(false);
  const [isSuccessful, setIsSuccessful] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const [errorMessage, setErrorMessage] = useState({
    title: "",
    body: "",
  });

  const [formData, setFormData] = useState({
    username: "",
    password: "",
    confirm_password: "",
  });

  const [showErrorToast, setShowErrorToast] = useState(false);

  const toggleErrorToast = () => setShowErrorToast(!showErrorToast);

  function showToastMessage(title, body) {
    setErrorMessage({
      title: title,
      body: body,
    });
    setShowErrorToast(true);
  }

  function handleChange(e) {
    const key = e.target.name;
    const value = e.target.value;
    setFormData({ ...formData, [key]: value });
    // reset error if username changes
    if (key === "username") {
      setIsExistingUser(false);
    }
  }

  useEffect(() => {
    // Update the document title using the browser API
    if (formData.password !== formData.confirm_password) {
      setDoPasswordsMatch(false);
    } else {
      setDoPasswordsMatch(true);
    }
  }, [formData.password, formData.confirm_password]);

  async function register(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }

    if (!doPasswordsMatch) {
      showToastMessage("Form Error", "Passwords do not match!");
      return;
    } else if (!formData.username || !formData.password) {
      showToastMessage("Form Error", "Details cannot be empty!");
      return;
    }
    setIsLoading(true);
    const res = await post_register({
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

    if (res.status === 409) {
      setIsExistingUser(true);
      return;
    }

    // handle success!
    setIsSuccessful(true);
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
        {isSuccessful ? (
          <div className="d-flex flex-column justify-content-around align-items-center">
            <div className="m-2">You have successfully registered!</div>
            <Link to="/">Back to login page</Link>
          </div>
        ) : (
          <div>
            <Form className="w-100" onSubmit={register}>
              <Form.Group className="mb-3" controlId="formGroupUsername">
                <Form.Label>Username</Form.Label>
                <Form.Control
                  name="username"
                  type="text"
                  placeholder="Enter username"
                  required
                  onChange={handleChange}
                  isInvalid={isExistingUser}
                />
                <Form.Control.Feedback type="invalid">
                  The user exists!
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
                />
              </Form.Group>
              <Form.Group className="mb-3" controlId="formGroupConfirmPassword">
                <Form.Label>Confirm Password</Form.Label>
                <Form.Control
                  name="confirm_password"
                  type="password"
                  placeholder="Confirm Password"
                  required
                  onChange={handleChange}
                  isInvalid={!doPasswordsMatch}
                />
                <Form.Control.Feedback type="invalid">
                  Passwords do not match!
                </Form.Control.Feedback>
              </Form.Group>
              <Button variant="primary" type="submit" className="w-100">
                Register
              </Button>
            </Form>
            {isLoading && (
              <div className="w-100 text-center mt-2">
                <Spinner animation="border" role="status" variant="secondary">
                  <span className="visually-hidden">Loading...</span>
                </Spinner>
              </div>
            )}
            <div></div>
            <div className="d-flex flex-row m-4 justify-content-around">
              <Link to="/">Back to login page</Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default RegisterPage;
