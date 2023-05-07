import axios from "axios";

const API_URL = "/api";
const TOKEN_EXPIRED = "TokenExpired";
const INVALID_CSRF = "InvalidCSRF";
const CSRF_TOKEN_HEADER = "csrf-token";
const CSRF_TOKEN_COOKIE = "csrf_token";

axios.defaults.withCredentials = true;

var promiseCache = null;
function refresh_access_token(fn) {
  if (promiseCache != null) return promiseCache;
  promiseCache = axios.get(API_URL + "/auth/access_token");
  promiseCache.then(
    function () {
      promiseCache = null;
    },
    function () {
      promiseCache = null;
    }
  );
  return promiseCache;
}

// Retrieve CSRF token from a cookie
function get_csrf_token() {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${CSRF_TOKEN_COOKIE}=`);
  if (parts.length === 2) {
    return parts.pop().split(';').shift();
  }

}

axios.interceptors.request.use(config => {
  // Retrieve the CSRF token from the cookie
  const csrfToken = get_csrf_token();
  if (csrfToken) {
    // Append the CSRF token as a custom header
    config.headers[CSRF_TOKEN_HEADER] = csrfToken;
  }
  return config;
});

axios.interceptors.response.use(
  function (response) {
    return response;
  },
  async function (error) {
    if (error.response) {
      if (
        error.response.status === 401 &&
        (error.response.data === TOKEN_EXPIRED ||
          error.response.data === INVALID_CSRF)
      ) {
        // token has expired;
        try {
          // attempting to refresh token;
          let res = await refresh_access_token();
          if (res.status === 200) {
            // refresh success, redo request!
            return await axios(error.config);
          }
        } catch (e) {
          // failed to refresh!
          return error.response;
        }
      }
      return error.response;
    } else {
      return Promise.reject(error);
    }
  }
);

async function make_post(route, data) {
  try {
    const res = await axios.post(API_URL + route, data);
    return res;
  } catch (error) {
    return error.response;
  }
}

async function make_put(route, params) {
  try {
    const res = await axios.put(API_URL + route, { params });
    return res;
  } catch (error) {
    return error.response;
  }
}

async function make_get(route, params) {
  try {
    const res = await axios.get(API_URL + route, { params });
    return res;
  } catch (error) {
    return error.response;
  }
}

async function make_delete(route) {
  try {
    const res = await axios.delete(API_URL + route);
    return res;
  } catch (error) {
    return error.response;
  }
}

export { make_post, make_get, make_put, make_delete, refresh_access_token };
