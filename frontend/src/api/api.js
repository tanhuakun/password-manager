import axios from "axios";

const API_URL = "http://localhost:8080/api";

axios.defaults.withCredentials = true;

async function make_post(route, data) {
  try {
    const res = await axios.post(API_URL + route, data);
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

export { make_post, make_get };
