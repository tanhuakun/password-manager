import React, { useState, useEffect } from "react";
import PasswordItem from "./components/PasswordItem";
import AddPasswordModal from "./components/AddPasswordModal";
import DeletePasswordModal from "./components/DeletePasswordModal";
import { Button, InputGroup, Accordion, Form, Spinner } from "react-bootstrap";
import { get_passwords } from "api/password";
import { toast } from "react-toastify";
import { useMasterPassword } from "hooks/useMasterPassword";
import { decryptPassword } from "utils/crypto";

function PasswordTablePage() {
  const [filterString, setFilterString] = useState("");
  const [passwordArray, setPasswordArray] = useState([]);
  const [isAddPasswordModalOpen, setIsAddPasswordModalOpen] = useState(false);
  const [isDeletePasswordModalOpen, setIsDeletePasswordModalOpen] =
    useState(false);
  const [selectedPasswordObj, setSelectedPasswordObj] = useState(null);
  const [isFetchingPasswords, setIsFetchingPasswords] = useState(true);
  const { masterPassword } = useMasterPassword();

  const passwordsDiv = passwordArray
    .filter((x) => x.purpose.toLowerCase().includes(filterString))
    .sort((a, b) => {
      if (a.purpose < b.purpose) {
        return -1;
      } else {
        return 1;
      }
    })
    .map((storedPasswordObj) => (
      <PasswordItem
        key={storedPasswordObj.id}
        storedPassword={storedPasswordObj}
        removePasswordById={removePasswordFromList}
        openDeletePasswordModal={openDeletePasswordModal}
      />
    ));

  async function fetchPasswords() {
    let res = await get_passwords();
    if (!res || res.status === 500) {
      toast.error("Server error!");
      return;
    }
    let decryptedPasswords = await Promise.all(
      res.data.map(async (x) => {
        x.password = await decryptPassword(masterPassword, x.password);
        return x;
      })
    );
    setPasswordArray(decryptedPasswords);
    setIsFetchingPasswords(false);
  }

  useEffect(() => {
    fetchPasswords();
    // eslint-disable-next-line
  }, []);

  function openAddPasswordModal() {
    setIsAddPasswordModalOpen(true);
  }
  function closeAddPasswordModal() {
    setIsAddPasswordModalOpen(false);
  }

  function openDeletePasswordModal(obj) {
    setSelectedPasswordObj(obj);
    setIsDeletePasswordModalOpen(true);
  }
  function closeDeletePasswordModal() {
    setIsDeletePasswordModalOpen(false);
  }

  function addPasswordToList(storedPasswordObj) {
    setPasswordArray([...passwordArray, storedPasswordObj]);
  }

  function removePasswordFromList(id) {
    setPasswordArray(passwordArray.filter((x) => x.id !== id));
  }

  function checkPurposeExists(purpose) {
    return passwordArray.find((x) => x.purpose === purpose) !== undefined;
  }

  return (
    <div className="w-100">
      {isFetchingPasswords ? (
        <div className="d-flex w-100 p-3 flex-column align-items-center justify-content-center">
          <div className="text-center">Loading...</div>
          <Spinner
            className="mt-4"
            animation="border"
            role="status"
            variant="secondary"
          />
        </div>
      ) : (
        <div className="d-flex w-100 p-3 flex-column align-items-center justify-content-center">
          <h6 className="display-6 w-75">Passwords</h6>
          <div className="w-75 mb-2 d-flex flex-row justify-content-between">
            <AddPasswordModal
              show={isAddPasswordModalOpen}
              handleClose={closeAddPasswordModal}
              checkPurposeExists={checkPurposeExists}
              addPassword={addPasswordToList}
            />
            <DeletePasswordModal
              show={isDeletePasswordModalOpen}
              handleClose={closeDeletePasswordModal}
              passwordObj={selectedPasswordObj}
              removePasswordFromList={removePasswordFromList}
            />
            <Button onClick={openAddPasswordModal} variant="primary">
              Add Password
            </Button>
            <InputGroup className="w-50">
              <Form.Control
                placeholder="Search"
                aria-label="Default"
                aria-describedby="inputGroup-sizing-default"
                onChange={(x) => setFilterString(x.target.value.toLowerCase())}
              />
            </InputGroup>
          </div>
          <Accordion className="w-75">{passwordsDiv}</Accordion>
        </div>
      )}
    </div>
  );
}

export default PasswordTablePage;
