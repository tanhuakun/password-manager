import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { post_register } from "api/authentication.js";
import Spinner from "react-bootstrap/Spinner";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import { toast } from "react-toastify";
import { clientPasswordHash } from "utils/crypto";

function RegisterPage() {
  const [doPasswordsMatch, setDoPasswordsMatch] = useState(true);
  const [isExistingUser, setIsExistingUser] = useState(false);
  const [isSuccessful, setIsSuccessful] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: "",
    password: "",
    confirm_password: "",
  });

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
      toast.warn("Passwords do not match!");
      return;
    } else if (!formData.username || !formData.password) {
      toast.warn("Details cannot be empty!");
      return;
    }
    setIsLoading(true);
    const submittedPasswordHash = await clientPasswordHash(formData.password);
    const res = await post_register({
      username: formData.username,
      password: submittedPasswordHash,
    });
    setIsLoading(false);

    if (res.status === 409) {
      setIsExistingUser(true);
      return;
    }

    if (!res || res.status !== 200) {
      toast.error("Server error!");
      return;
    }

    // handle success!
    setIsSuccessful(true);
  }

  return (
    <div className="d-flex h-100 p-3 d-flex align-items-center justify-content-center">
      <div className="frontpage_box h-75">
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
                <Form.Label>Master Password</Form.Label>
                <Form.Control
                  name="password"
                  type="password"
                  placeholder="Master Password"
                  required
                  onChange={handleChange}
                />
              </Form.Group>
              <Form.Group className="mb-3" controlId="formGroupConfirmPassword">
                <Form.Label>Confirm Master Password</Form.Label>
                <Form.Control
                  name="confirm_password"
                  type="password"
                  placeholder="Confirm Master Password"
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
