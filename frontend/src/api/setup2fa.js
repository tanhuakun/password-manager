import { make_post, make_get, make_put } from "./api.js";

async function get_2fa_url() {
  return await make_get("/2fa/2fa_url", {});
}

async function post_finalise_2fa_secret(details) {
  return await make_post("/2fa/finalise_2fa_secret", details);
}

async function put_disable_2fa() {
  return await make_put("/2fa/disable_2fa", {});
}

export { get_2fa_url, post_finalise_2fa_secret, put_disable_2fa};
