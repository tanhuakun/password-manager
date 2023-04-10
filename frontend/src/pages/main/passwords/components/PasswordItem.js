import { React, useState } from "react";
import {
  Accordion,
  OverlayTrigger,
  Tooltip,
  Form,
  InputGroup,
} from "react-bootstrap";
import { Trash, Eye, EyeSlashFill } from "react-bootstrap-icons";

function PasswordItem({ storedPassword, openDeletePasswordModal }) {
  const [passwordTextType, setPasswordTextType] = useState("password");
  const togglePasswordVisiblity = () => {
    if (passwordTextType === "password") {
      setPasswordTextType("text");
      return;
    }
    setPasswordTextType("password");
  };

  return (
    <Accordion.Item
      eventKey={storedPassword.id}
      className="mt-2"
      style={{ border: "1px solid gray" }}
    >
      <Accordion.Header>{storedPassword.purpose}</Accordion.Header>
      <Accordion.Body>
        <div className="d-flex justify-content-between align-items-center">
          <Form.Group className="w-75">
            <InputGroup>
              <Form.Control
                value={storedPassword.password}
                disabled
                type={passwordTextType}
              />
              <InputGroup.Text
                id="basic-addon2"
                onClick={togglePasswordVisiblity}
              >
                {passwordTextType === "password" ? <Eye /> : <EyeSlashFill />}
              </InputGroup.Text>
            </InputGroup>
          </Form.Group>
          <OverlayTrigger
            placement="bottom"
            delay={{ show: 100, hide: 400 }}
            overlay={<Tooltip>Delete this password?</Tooltip>}
          >
            <Trash
              color="red"
              size={24}
              style={{ cursor: "grab" }}
              onClick={() => openDeletePasswordModal(storedPassword)}
            />
          </OverlayTrigger>
        </div>
      </Accordion.Body>
    </Accordion.Item>
  );
}

export default PasswordItem;
