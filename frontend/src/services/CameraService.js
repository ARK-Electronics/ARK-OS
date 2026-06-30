import axios from 'axios';

const ENDPOINTS = {
  cameras: `/api/camera/cameras`,
  select: `/api/camera/select`,
};

export default {
  // { cameras: [{ path, index, name, type, selected }], configured }
  async getCameras() {
    return axios.get(ENDPOINTS.cameras);
  },
  // device: "/dev/videoN", or "" to revert to auto-select. Restarts the rtsp-server.
  async selectCamera(device) {
    return axios.post(ENDPOINTS.select, { device });
  },
};
