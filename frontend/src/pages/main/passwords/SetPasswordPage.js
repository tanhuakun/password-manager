import {
  get_check_master_password,
  post_set_master_password,
  post_verify_master_password,
} from "api/password";
import { React, useEffect, useState } from "react";
import { toast } from "react-toastify";
import Spinner from "react-bootstrap/Spinner";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import { clientPasswordHash } from "utils/crypto";
import { useMasterPassword } from "hooks/useMasterPassword";

function SetPasswordPage() {
  const { setMasterPassword } = useMasterPassword();
  const [hasUserSetPassword, setHasUserSetPassword] = useState(false);
  const [doPasswordsMatch, setDoPasswordsMatch] = useState(true);
  const [isFetchingMasterPassword, setIsFetchingMasterPassword] =
    useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [newPassFormData, setNewPassFormData] = useState({
    password: "",
    confirm_password: "",
  });
  const [isInvalidPassword, setIsInvalidPassword] = useState(false);

  const [formPassword, setFormPassword] = useState("");

  useEffect(() => {
    async function fetchMasterPassword() {
      setIsLoading(true);
      let res = await get_check_master_password();

      if (!res || res.status !== 200) {
        toast.error("Server error!");
        return;
      }
      if (res.data.result === "true") {
        res.data.result = true;
      } else if (res.data.result === "false") {
        res.data.result = false;
      }
      setHasUserSetPassword(res.data.result);
      setIsLoading(false);
      setIsFetchingMasterPassword(false);
    }
    fetchMasterPassword();
  }, []);

  useEffect(() => {
    // Update the document title using the browser API
    if (newPassFormData.password !== newPassFormData.confirm_password) {
      setDoPasswordsMatch(false);
    } else {
      setDoPasswordsMatch(true);
    }
  }, [newPassFormData.password, newPassFormData.confirm_password]);

  function newPassHandleChange(e) {
    const key = e.target.name;
    const value = e.target.value;
    setNewPassFormData({ ...newPassFormData, [key]: value });
  }

  function passHandleChange(e) {
    setIsInvalidPassword(false);
    setFormPassword(e.target.value);
  }

  async function verifySetPassword(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }
    setIsLoading(true);
    const submittedPassword = formPassword;
    const submittedPasswordHash = await clientPasswordHash(submittedPassword);
    const res = await post_verify_master_password({
      password: submittedPasswordHash,
    });
    setIsLoading(false);

    if (!res || res.status !== 200) {
      toast.error("Server error!");
      return;
    }

    if (res.data.result === "true") {
      res.data.result = true;
    } else if (res.data.result === "false") {
      res.data.result = false;
    }

    if (!res.data.result) {
      setIsInvalidPassword(true);
      return;
    }
    setFormPassword("");
    setMasterPassword(submittedPassword);
  }

  async function updatePassword(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }

    if (!doPasswordsMatch) {
      toast.warn("Passwords do not match!");
      return;
    }
    setIsLoading(true);
    const submittedPassword = newPassFormData.password;
    const submittedPasswordHash = await clientPasswordHash(submittedPassword);
    const res = await post_set_master_password({
      password: submittedPasswordHash,
    });
    setIsLoading(false);

    if (res.status === 409) {
      console.log("This shouldn't happen! Password should not be set");
      return;
    }

    if (!res || res.status !== 200) {
      toast.error("Server error!");
      return;
    }

    setNewPassFormData({
      password: "",
      confirm_password: "",
    });
    event.target.reset();
    setHasUserSetPassword(true);
  }

  return (
    <div className="w-50">
      {isFetchingMasterPassword ? (
        <div className="text-center">Loading...</div>
      ) : hasUserSetPassword ? (
        <div>
          <div className="my-4 text-center">
            Key in your master password to begin.
          </div>
          <Form className="w-100" onSubmit={verifySetPassword}>
            <Form.Group className="mb-3" controlId="formGroupVerifyPassword">
              <Form.Label>Master Password</Form.Label>
              <Form.Control
                name="verify_password"
                type="password"
                placeholder="Master Password"
                required
                onChange={passHandleChange}
                isInvalid={isInvalidPassword}
              />
              <Form.Control.Feedback type="invalid">
                Incorrect Password!
              </Form.Control.Feedback>
            </Form.Group>
            <Button variant="primary" type="submit" className="w-100">
              Enter Master Password
            </Button>
          </Form>
        </div>
      ) : (
        <div>
          <div className="my-4 text-center">
            To begin using password manager, please setup your master password!
            <br />
            Your master password is very important, so please set a long but
            memorable one.
          </div>
          <Form className="w-100" onSubmit={updatePassword}>
            <Form.Group className="mb-3" controlId="formGroupPassword">
              <Form.Label>Password</Form.Label>
              <Form.Control
                name="password"
                type="password"
                placeholder="Master Password"
                required
                onChange={newPassHandleChange}
              />
            </Form.Group>
            <Form.Group className="mb-3" controlId="formGroupConfirmPassword">
              <Form.Label>Confirm Password</Form.Label>
              <Form.Control
                name="confirm_password"
                type="password"
                placeholder="Confirm Master Password"
                required
                onChange={newPassHandleChange}
                isInvalid={!doPasswordsMatch}
              />
              <Form.Control.Feedback type="invalid">
                Passwords do not match!
              </Form.Control.Feedback>
            </Form.Group>
            <Button variant="primary" type="submit" className="w-100">
              Set Master Password
            </Button>
          </Form>
        </div>
      )}
      {isLoading && (
        <div className="w-100 text-center mt-2">
          <Spinner animation="border" role="status" variant="secondary">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </div>
      )}
    </div>
  );
}

export default SetPasswordPage;
