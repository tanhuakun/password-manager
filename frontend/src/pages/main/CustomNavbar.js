import Container from "react-bootstrap/Container";
import Nav from "react-bootstrap/Nav";
import Navbar from "react-bootstrap/Navbar";
import { useNavigate } from "react-router-dom";
import { Outlet } from "react-router-dom";
import { post_logout } from "api/authentication";
import { toast } from "react-toastify";

function CustomNavbar() {
  const navigate = useNavigate();

  async function logout() {
    let res = await post_logout();
    if (!res || res.status === 500) {
      toast.error("Server error!");
    }

    // nothing to do, let app refresh handle resetting state
    window.location.href = "/";
  }

  return (
    <div>
      <Navbar bg="light" expand="lg" onSelect={console.log}>
        <Container>
          <Navbar.Brand>Password Manager</Navbar.Brand>
          <Navbar.Toggle aria-controls="basic-navbar-nav" />
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="me-auto">
              <Nav.Link onClick={() => navigate("/home")}>Home</Nav.Link>
              <Nav.Link onClick={() => navigate("/2fa")}>2FA</Nav.Link>
            </Nav>
          </Navbar.Collapse>
          <Navbar.Collapse
            id="basic-navbar-nav-logout"
            className="justify-content-end"
          >
            <Nav className="justify-content-end">
              <Nav.Link onClick={logout}>Logout</Nav.Link>
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>
      <Outlet />
    </div>
  );
}

export default CustomNavbar;
