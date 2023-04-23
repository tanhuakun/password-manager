import {
  get_2fa_url,
  post_finalise_2fa_secret,
  delete_2fa_enabled,
} from "api/setup2fa";
import { useEffect, useState } from "react";
import QRCode from "react-qr-code";
import Form from "react-bootstrap/Form";
import Button from "react-bootstrap/Button";
import Spinner from "react-bootstrap/Spinner";
import { toast } from 'react-toastify';

function TwoFactorAuthPage() {
  const [isFetchingQRUrl, setIsFetchingQRUrl] = useState(true);
  const [is2FASetUp, setIs2FASetUp] = useState(false);
  const [QRCodeURL, setQRCodeURL] = useState("");
  const [isLoadingRequest, setIsLoadingRequest] = useState(false);
  const [enteredCode, setEnteredCode] = useState("");
  const [enteredConfirmation, setEnteredConfirmation] = useState("");
  const [showInvalidCode, setShowInvalidCode] = useState(false);
  const [showInvalidConfirm, setShowInvalidConfirm] = useState(false);
  const [isInternalServerError, setIsInternalServerError] = useState(false);

  async function get_and_display_qrcode() {
    setIsInternalServerError(false);
    setIsLoadingRequest(true);
    let res = await get_2fa_url();
    setIsLoadingRequest(false);

    if (res.status === 409) {
      // Exists!
      setIs2FASetUp(true);
      setIsFetchingQRUrl(false);
      return;
    }

    if (!res || res.status !== 200) {
      setIsInternalServerError(true);
      toast.error('Server error!');
      return;
    }

    let url = res.data.url;
    setQRCodeURL(url);
    setIsFetchingQRUrl(false);
  }

  useEffect(() => {
    get_and_display_qrcode();
  }, []);

  async function submitCode(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }
    setIsInternalServerError(false);
    setShowInvalidCode(false);
    setIsLoadingRequest(true);
    let res = await post_finalise_2fa_secret({ code: enteredCode });
    setIsLoadingRequest(false);

    if (res.status === 403) {
      setShowInvalidCode(true);
      return;
    }

    if (res.status === 409) {
      console.log("2FA has already been setup, frontend issue");
    }

    if (!res || res.status !== 200) {
      toast.error('Server error!');
      setIsInternalServerError(true);
      return;
    }

    setIs2FASetUp(true);
    setEnteredCode("");
  }

  async function submitRemove2FA(event) {
    const form = event.currentTarget;
    event.preventDefault();
    event.stopPropagation();
    if (form.checkValidity() === false) {
      return;
    }
    setIsInternalServerError(false);
    if (enteredConfirmation !== "confirm") {
      setShowInvalidConfirm(true);
      return;
    }

    setIsLoadingRequest(true);
    let res = await delete_2fa_enabled();
    setIsLoadingRequest(false);

    if (!res || res.status !== 200) {
      toast.error('Server error!');
      setIsInternalServerError(true);
      return;
    }

    setIs2FASetUp(false);
    setIsFetchingQRUrl(true);
    setEnteredConfirmation("");

    get_and_display_qrcode();
  }

  return (
    <div className="d-flex flex-column align-items-center justify-content-center">
      {isFetchingQRUrl ? (
        <div className="w-100 d-flex flex-column align-items-center justify-content-center">
          <div className="my-4">Getting 2FA details...</div>
        </div>
      ) : is2FASetUp ? (
        <div className="w-100 d-flex flex-column align-items-center justify-content-center">
          <div className="my-4">2FA setup has been completed, remove it?</div>
          <Form className="w-25 mt-4" onSubmit={submitRemove2FA}>
            <Form.Group className="mb-3" controlId="formGroupUsername">
              <Form.Label>Enter The Word "confirm" Below</Form.Label>
              <Form.Control
                name="code"
                type="text"
                placeholder="confirm"
                required
                onChange={(x) => {
                  setEnteredConfirmation(x.target.value);
                  setShowInvalidConfirm(false);
                }}
                isInvalid={showInvalidConfirm}
              />
              <Form.Control.Feedback type="invalid">
                Please type "confirm" above!
              </Form.Control.Feedback>
            </Form.Group>
            <Button variant="primary" type="submit" className="w-100">
              Remove 2FA
            </Button>
          </Form>
        </div>
      ) : (
        <div className="w-100 d-flex flex-column align-items-center justify-content-center">
          <div className="my-4 text-center">
            To setup 2FA, add the QR code using your authenticator app.
            <br />
            After setting up, key in the current code in the form below to
            confirm your setup!
          </div>
          <QRCode value={QRCodeURL} />
          <Form className="w-25 mt-4" onSubmit={submitCode}>
            <Form.Group className="mb-3" controlId="formGroupUsername">
              <Form.Label>Authenticator Code Confirmation</Form.Label>
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
              Confirm Code
            </Button>
          </Form>
        </div>
      )}
      {isLoadingRequest && (
        <Spinner animation="border" role="status" variant="secondary" />
      )}
      {isInternalServerError && (
        <div className="text-danger">Something went wrong!</div>
      )}
    </div>
  );
}

export default TwoFactorAuthPage;
