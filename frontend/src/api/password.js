import { make_post, make_get, make_delete } from "./api.js";

async function get_check_master_password() {
  return await make_get("/passwords/check_master_password_set", {});
}

async function post_set_master_password(details) {
  return await make_post("/passwords/set_master_password", details);
}

async function post_verify_master_password(details) {
  return await make_post("/passwords/verify_master_password", details);
}

async function post_add_password(details) {
  return await make_post("/passwords/add_password", details);
}

async function get_passwords() {
  return await make_get("/passwords/", {});
}

async function delete_password(id) {
  return await make_delete(`/passwords/password/${id}`);
}

export {
  get_check_master_password,
  post_set_master_password,
  post_verify_master_password,
  post_add_password,
  get_passwords,
  delete_password,
};
