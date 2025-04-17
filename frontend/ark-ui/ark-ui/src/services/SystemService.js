import axios from 'axios';

const ENDPOINTS = {
  info: `/api/system/info`,
  hostname: `/api/system/hostname`,
};

export default {
  async getSystemInfo() {
    return axios.get(ENDPOINTS.info);
  },

  async changeHostname(hostname) {
    return axios.post(ENDPOINTS.hostname, { hostname });
  },
};
