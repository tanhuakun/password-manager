import { make_post, make_get } from "./api.js";

async function post_login(details) {
  return await make_post("/login", details);
}

async function post_register(details) {
  return await make_post("/register", details);
}

async function post_google_login(details) {
  return await make_post("/google_login", details);
}

async function check_login() {
  return await make_get("/check_login", {});
}

export { post_login, post_register, post_google_login, check_login };
