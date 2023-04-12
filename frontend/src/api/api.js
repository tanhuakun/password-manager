import axios from "axios";

const API_URL = "http://localhost:8080/api";
const TOKEN_EXPIRED = "TokenExpired";

axios.defaults.withCredentials = true;

var promiseCache = null;
function refresh_access_token(fn) {
  console.log("yo");
  if (promiseCache != null) return promiseCache;
  promiseCache = axios.get(API_URL + "/auth/access_token");
  promiseCache.then(
    function () {
      console.log("hello");
      promiseCache = null;
    },
    function () {
      promiseCache = null;
    }
  );
  return promiseCache;
}

axios.interceptors.response.use(
  function (response) {
    return response;
  },
  async function (error) {
    if (error.response) {
      if (
        error.response.status === 401 &&
        error.response.data === TOKEN_EXPIRED
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
      return error;
    }
  }
);

async function make_post(route, data) {
  try {
    const res = await axios.post(API_URL + route, data);
    return res;
  } catch (error) {
    console.log(error);
    return error.response;
  }
}

async function make_put(route, params) {
  try {
    const res = await axios.put(API_URL + route, { params });
    return res;
  } catch (error) {
    console.log(error);
    return error.response;
  }
}

async function make_get(route, params) {
  try {
    const res = await axios.get(API_URL + route, { params });
    return res;
  } catch (error) {
    console.log(error);
    return error.response;
  }
}

async function make_delete(route) {
  try {
    const res = await axios.delete(API_URL + route);
    return res;
  } catch (error) {
    console.log(error);
    return error.response;
  }
}

export { make_post, make_get, make_put, make_delete, refresh_access_token };
