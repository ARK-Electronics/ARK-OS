import axios from 'axios';

const ENDPOINTS = {
  details: `/api/autopilot/details`,
  firmwareUpload: `/api/autopilot/firmware-upload`,
  resetFmu: `/api/autopilot/reset-fmu`,
  resetFmuBootloader: `/api/autopilot/reset-fmu-bootloader`,
};

export default {
  async getAutopilotDetails() {
    return axios.get(ENDPOINTS.details);
  },
  async uploadFirmware(formData) {
    return axios.post(ENDPOINTS.firmwareUpload, formData, {
      headers: {'Content-Type': 'multipart/form-data'}
    });
  },
  async resetFmu() {
    return axios.post(ENDPOINTS.resetFmu);
  },
  async resetFmuBootloader() {
    return axios.post(ENDPOINTS.resetFmuBootloader);
  }
};
