import { make_post, make_get } from "./api.js";

async function get_check_master_password() {
  return await make_get("/passwords/check_master_password_set", {});
}

async function post_set_master_password(details) {
  return await make_post("/passwords/set_master_password", details);
}

async function post_verify_master_password(details) {
  return await make_post("/passwords/verify_master_password", details);
}

export {
  get_check_master_password,
  post_set_master_password,
  post_verify_master_password,
};
