import { post_verify_2fa } from "api/authentication";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import Spinner from "react-bootstrap/Spinner";
import { toast } from "react-toastify";

function Verify2FAPage() {
  const [enteredCode, setEnteredCode] = useState("");
  const [showInvalidCode, setShowInvalidCode] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isRelogin, setIsRelogin] = useState(false);
  const navigate = useNavigate();

  async function submitCode(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }
    setShowInvalidCode(false);
    setIsLoading(true);
    let res = await post_verify_2fa({ code: enteredCode });
    setIsLoading(false);

    if (!res || res.status === 500) {
      toast.error("Server error! Please try again later");
      return;
    }

    if (res.status === 403) {
      setShowInvalidCode(true);
      return;
    }

    if (res.status === 401) {
      setIsRelogin(true);
      return;
    }

    navigate("/home");
  }

  return (
    <div className="d-flex flex-column h-100 p-3 align-items-center justify-content-center">
      {isRelogin ? (
        <div className="d-flex w-100 p-3 flex-column align-items-center justify-content-center">
          <p>Timer expired, please relogin</p>
          <Link to="/">To Login Page</Link>
        </div>
      ) : (
        <Form className="w-25 mt-4" onSubmit={submitCode}>
          <Form.Group className="mb-3" controlId="formGroupUsername">
            <Form.Label>Authenticator Code</Form.Label>
            <Form.Control
              name="code"
              type="text"
              placeholder="Enter Authenticator Code"
              required
              onChange={(x) => {
                setEnteredCode(x.target.value);
                setShowInvalidCode(false);
              }}
              isInvalid={showInvalidCode}
            />
            <Form.Control.Feedback type="invalid">
              Incorrect Code!
            </Form.Control.Feedback>
          </Form.Group>
          <Button variant="primary" type="submit" className="w-100">
            Submit Code
          </Button>
        </Form>
      )}
      {isLoading && (
        <Spinner
          className="mt-4"
          animation="border"
          role="status"
          variant="secondary"
        />
      )}
    </div>
  );
}

export default Verify2FAPage;
