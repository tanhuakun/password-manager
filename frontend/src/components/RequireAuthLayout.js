import { useNavigate, Outlet } from "react-router-dom";
import { useEffect } from "react";
import { useAuth } from "hooks/useAuth";

function RequireAuthLayout() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isAuthenticated) {
      navigate("/");
    }
  });

  return <div>{isAuthenticated && <Outlet />}</div>;
}

export default RequireAuthLayout;
