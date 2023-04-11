import { make_post, make_get } from "./api.js";

async function post_login(details) {
  return await make_post("/auth/login", details);
}

async function post_register(details) {
  return await make_post("/auth/register", details);
}

async function post_google_login(details) {
  return await make_post("/auth/google_login", details);
}

async function check_login() {
  return await make_get("/auth/is_login", {});
}

async function post_verify_2fa(details) {
  return await make_post("/auth/verify_2fa", details);
}

export { post_login, post_register, post_google_login, check_login, post_verify_2fa};
