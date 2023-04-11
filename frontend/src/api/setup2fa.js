import { make_post, make_get, make_delete } from "./api.js";

async function get_2fa_url() {
  return await make_get("/2fa/2fa_url", {});
}

async function post_finalise_2fa_secret(details) {
  return await make_post("/2fa/2fa_secret", details);
}

async function delete_2fa_enabled() {
  return await make_delete("/2fa/2fa_enabled");
}

export { get_2fa_url, post_finalise_2fa_secret, delete_2fa_enabled};
