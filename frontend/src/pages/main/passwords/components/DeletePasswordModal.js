import { Modal, Button, Spinner } from "react-bootstrap";
import { delete_password } from "api/password";
import { useState } from "react";
import { toast } from "react-toastify";

function DeletePasswordModal({
  show,
  handleClose,
  passwordObj,
  removePasswordFromList,
}) {
  const [isLoading, setIsLoading] = useState(false);

  async function deletePassword() {
    setIsLoading(true);
    let res = await delete_password(passwordObj.id);
    console.log(res);
    if (!res || res.status === 500) {
      toast.error("Server error!");
      return;
    }
    setIsLoading(false);
    removePasswordFromList(passwordObj.id);
    handleClose();
  }

  return (
    <Modal show={show} onHide={handleClose}>
      <Modal.Header closeButton>
        <Modal.Title>
          Delete {passwordObj != null ? passwordObj.purpose : ""} password
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Button
          variant="danger"
          type="submit"
          className="w-100"
          onClick={deletePassword}
        >
          Confirm Delete?
        </Button>
        {isLoading && (
          <div className="w-100 text-center mt-2">
            <Spinner animation="border" role="status" variant="secondary" />
          </div>
        )}
      </Modal.Body>
    </Modal>
  );
}

export default DeletePasswordModal;
