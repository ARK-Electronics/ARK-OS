import axios from 'axios';

const ENDPOINTS = {
  connections: `/api/network/connections`,
  connectionUpdate: (name) => `/api/network/connections/${name}`,
  connectConnection: (name) => `/api/network/connections/${name}/connect`,
  disconnectConnection: (name) => `/api/network/connections/${name}/disconnect`,
  wifiScan: `/api/network/wifi/scan`,
  usage: `/api/network/usage`,
  hostname: `/api/network/hostname`,
  lteStatus: `/api/network/lte/status`,
};

export default {
  async getConnections() {
    return axios.get(ENDPOINTS.connections);
  },
  async createConnection(config) {
    return axios.post(ENDPOINTS.connections, config);
  },
  async deleteConnection(name) {
    return axios.delete(ENDPOINTS.connectionUpdate(name));
  },
  async updateConnection(name, config) {
    return axios.put(ENDPOINTS.connectionUpdate(name), config);
  },
  async connectConnection(name) {
    return axios.post(ENDPOINTS.connectConnection(name));
  },
  async disconnectConnection(name) {
    return axios.post(ENDPOINTS.disconnectConnection(name));
  },
  async scanWifiNetworks() {
    return axios.get(ENDPOINTS.wifiScan);
  },
  async getHostname() {
    return axios.get(ENDPOINTS.hostname);
  },
  async setHostname(hostname) {
    return axios.post(ENDPOINTS.hostname, { hostname });
  },
  async getLteStatus() {
    return axios.get(ENDPOINTS.lteStatus);
  },
};
