import { Button, Modal, Form, Spinner, InputGroup } from "react-bootstrap";
import { useState, useEffect } from "react";
import { EyeSlashFill, Eye } from "react-bootstrap-icons";
import {
  generateRandomPassword,
  encryptPassword,
  decryptPassword,
} from "utils/crypto";
import { useMasterPassword } from "hooks/useMasterPassword";
import { post_add_password } from "api/password";
import { toast } from "react-toastify";

function AddPasswordModal({
  show,
  handleClose,
  checkPurposeExists,
  addPassword,
}) {
  const { masterPassword } = useMasterPassword();
  const [doPasswordsMatch, setDoPasswordsMatch] = useState(true);
  const [isExistingPurpose, setIsExistingPurpose] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [passwordTextType, setPasswordTextType] = useState("password");
  const [passwordLength, setPasswordLength] = useState(18);
  const [formData, setFormData] = useState({
    purpose: "",
    password: "",
    confirm_password: "",
  });

  function resetState() {
    setFormData({
      purpose: "",
      password: "",
      confirm_password: "",
    });
    setPasswordTextType("password");
  }

  async function submitAddPassword(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }

    if (!doPasswordsMatch) {
      toast.warning("Passwords do not match!");
      return;
    }

    if (isExistingPurpose) {
      toast.warning("There is a password entry for this purpose!");
      return;
    }

    setIsLoading(true);
    let encryptedPassword = await encryptPassword(
      masterPassword,
      formData.password
    );

    let res = await post_add_password({
      purpose: formData.purpose,
      password: encryptedPassword,
    });
    setIsLoading(false);
   
    if (res.status === 409) {
      console.log("This shouldn't happen! Frontend error");
      return;
    }

    if (!res || res.status !== 200) {
      toast.error("Server error!");
      return;
    } 

    let passwordObj = res.data;
    passwordObj.password = await decryptPassword(
      masterPassword,
      passwordObj.password
    );
    addPassword(passwordObj);
    resetState();
    handleClose();
  }

  function handleChange(e) {
    const key = e.target.name;
    const value = e.target.value;
    setFormData({ ...formData, [key]: value });
    // reset error if username changes
    if (key === "purpose") {
      if (checkPurposeExists(value)) {
        setIsExistingPurpose(true);
      } else {
        setIsExistingPurpose(false);
      }
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

  const togglePasswordVisiblity = () => {
    if (passwordTextType === "password") {
      setPasswordTextType("text");
      return;
    }
    setPasswordTextType("password");
  };

  function generatePassword() {
    let pass = generateRandomPassword(passwordLength);
    setFormData({
      ...formData,
      password: pass,
      confirm_password: pass,
    });
  }

  return (
    <Modal show={show} onHide={handleClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>Add New Password</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form className="w-100" onSubmit={submitAddPassword}>
          <Form.Group className="mb-3" controlId="formGroupPurpose">
            <Form.Label>Purpose</Form.Label>
            <Form.Control
              name="purpose"
              type="text"
              placeholder="Enter Password Purpose, eg. Instagram"
              required
              onChange={handleChange}
              isInvalid={isExistingPurpose}
            />
            <Form.Control.Feedback type="invalid">
              There is already a password for this purpose!
            </Form.Control.Feedback>
          </Form.Group>
          <div className="d-flex flex-row justify-content-between mt-5">
            <Button
              variant="secondary"
              className="mb-3"
              onClick={generatePassword}
            >
              Generate Password
            </Button>
            <div className="w-50">
              <div>Set Password Length: {passwordLength}</div>
              <Form.Range
                min={6}
                max={30}
                onChange={(x) => setPasswordLength(parseInt(x.target.value))}
              />
            </div>
          </div>
          <Form.Group className="mb-3" controlId="formGroupPassword">
            <Form.Label>Password</Form.Label>
            <InputGroup>
              <Form.Control
                name="password"
                type={passwordTextType}
                placeholder="Password"
                required
                onChange={handleChange}
                value={formData.password}
              />
              <InputGroup.Text
                id="basic-addon2"
                onClick={togglePasswordVisiblity}
              >
                {passwordTextType === "password" ? <Eye /> : <EyeSlashFill />}
              </InputGroup.Text>
            </InputGroup>
          </Form.Group>
          <Form.Group className="mb-3" controlId="formGroupConfirmPassword">
            <Form.Label>Confirm Password</Form.Label>
            <Form.Control
              name="confirm_password"
              type={passwordTextType}
              placeholder="Confirm Password"
              required
              onChange={handleChange}
              value={formData.confirm_password}
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
      </Modal.Body>
    </Modal>
  );
}

export default AddPasswordModal;
