import axios from 'axios';

const ENDPOINTS = {
  statuses: `/api/service/statuses`,
  start: (serviceName) => `/api/service/start?serviceName=${serviceName}`,
  stop: (serviceName) => `/api/service/stop?serviceName=${serviceName}`,
  restart: (serviceName) => `/api/service/restart?serviceName=${serviceName}`,
  enable: (serviceName) => `/api/service/enable?serviceName=${serviceName}`,
  disable: (serviceName) => `/api/service/disable?serviceName=${serviceName}`,
  logs: (serviceName) => `/api/service/logs?serviceName=${serviceName}`,
  config: (serviceName) => `/api/service/config?serviceName=${serviceName}`,
};

export default {
  async getServiceStatuses() {
    return axios.get(ENDPOINTS.statuses);
  },
  async startService(serviceName) {
    return axios.post(ENDPOINTS.start(serviceName));
  },
  async stopService(serviceName) {
    return axios.post(ENDPOINTS.stop(serviceName));
  },
  async restartService(serviceName) {
    return axios.post(ENDPOINTS.restart(serviceName));
  },
  async enableService(serviceName) {
    return axios.post(ENDPOINTS.enable(serviceName));
  },
  async disableService(serviceName) {
    return axios.post(ENDPOINTS.disable(serviceName));
  },
  async getServiceLogs(serviceName) {
    return axios.get(ENDPOINTS.logs(serviceName));
  },
  async getServiceConfig(serviceName) {
    return axios.get(ENDPOINTS.config(serviceName));
  },
  async saveServiceConfig(serviceName, config) {
    return axios.post(ENDPOINTS.config(serviceName), { config });
  },
};
