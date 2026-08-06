import axios from 'axios';

const ENDPOINTS = {
  logs: `/api/logloader/logs`,
  status: `/api/logloader/status`,
  events: `/api/logloader/events`,
  refresh: `/api/logloader/refresh`,
  download: `/api/logloader/logs/download`,
  upload: `/api/logloader/logs/upload`,
  cancel: `/api/logloader/logs/cancel`,
  localFile: (id) => `/api/logloader/logs/${id}/file`,
};

export default {
  async getLogs() {
    return axios.get(ENDPOINTS.logs);
  },

  async getStatus() {
    return axios.get(ENDPOINTS.status);
  },

  // Asks logloader to list the vehicle again — nothing polls, so this is how
  // the page gets a current listing. Changes arrive over /events.
  async refresh() {
    return axios.post(ENDPOINTS.refresh);
  },

  // Queues a download, and an upload of the same logs unless upload is false.
  async requestDownload(ids, upload = true) {
    return axios.post(ENDPOINTS.download, { ids, upload });
  },

  async requestDownloadAll(upload = true) {
    return axios.post(ENDPOINTS.download, { all: true, upload });
  },

  async requestUpload(ids, targets) {
    return axios.post(ENDPOINTS.upload, targets && targets.length ? { ids, targets } : { ids });
  },

  async cancelRequests(ids) {
    return axios.post(ENDPOINTS.cancel, { ids });
  },

  async deleteLocalFile(id) {
    return axios.delete(ENDPOINTS.localFile(id));
  },

  eventsUrl() {
    return ENDPOINTS.events;
  },
};
