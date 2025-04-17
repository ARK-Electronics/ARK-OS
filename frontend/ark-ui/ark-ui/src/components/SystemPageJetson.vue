<template>
  <div class="page-container">
    <!-- Header -->
    <h1 class="page-title">Jetson System Information</h1>

    <div v-if="loading" class="loading-container">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Loading system information...</p>
    </div>

    <div v-else class="system-content">
      <!-- System Details Grid -->
      <div class="system-grid">
        <!-- Hardware Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-microchip icon-color"></i>
            <span class="header-title">Hardware</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">Model:</span>
              <span class="info-value">{{ systemInfo.hardware.model }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Module:</span>
              <span class="info-value">{{ systemInfo.hardware.module }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Serial:</span>
              <span class="info-value">{{ systemInfo.hardware.serial_number }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">L4T:</span>
              <span class="info-value">{{ systemInfo.hardware.l4t }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">JetPack:</span>
              <span class="info-value">{{ systemInfo.hardware.jetpack }}</span>
            </div>
          </div>
        </div>

        <!-- Platform Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-server icon-color"></i>
            <span class="header-title">Platform</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">Distribution:</span>
              <span class="info-value">{{ systemInfo.platform.distribution }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Release:</span>
              <span class="info-value">{{ systemInfo.platform.release }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Python:</span>
              <span class="info-value">{{ systemInfo.platform.python }}</span>
            </div>
          </div>
        </div>

        <!-- Libraries Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-book icon-color"></i>
            <span class="header-title">Libraries</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">CUDA:</span>
              <span class="info-value">{{ systemInfo.libraries.cuda }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">OpenCV:</span>
              <span class="info-value">{{ systemInfo.libraries.opencv }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">OpenCV-CUDA:</span>
              <span class="info-value">{{ systemInfo.libraries.opencv_cuda ? 'Yes' : 'No' }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">cuDNN:</span>
              <span class="info-value">{{ systemInfo.libraries.cudnn }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">TensorRT:</span>
              <span class="info-value">{{ systemInfo.libraries.tensorrt }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">VPI:</span>
              <span class="info-value">{{ systemInfo.libraries.vpi }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Vulkan:</span>
              <span class="info-value">{{ systemInfo.libraries.vulkan }}</span>
            </div>
          </div>
        </div>

        <!-- Power & Temperature Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-bolt icon-color"></i>
            <span class="header-title">Power & Temperature</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">Power Mode:</span>
              <span class="info-value">{{ systemInfo.power.nvpmodel }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Jetson Clocks:</span>
              <span class="info-value">{{ systemInfo.power.jetson_clocks ? 'Enabled' : 'Disabled' }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Power Draw:</span>
              <span class="info-value">{{ (systemInfo.power.total / 1000).toFixed(2) }} W</span>
            </div>
            <div class="info-row">
              <span class="info-label">CPU Temp:</span>
              <span class="info-value">{{ systemInfo.power.temperature.cpu.toFixed(1) }}°C</span>
            </div>
            <div class="info-row">
              <span class="info-label">GPU Temp:</span>
              <span class="info-value">{{ systemInfo.power.temperature.gpu.toFixed(1) }}°C</span>
            </div>
            <div class="info-row">
              <span class="info-label">Junction Temp:</span>
              <span class="info-value">{{ systemInfo.power.temperature.tj.toFixed(1) }}°C</span>
            </div>
          </div>
        </div>

        <!-- Network Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-network-wired icon-color"></i>
            <span class="header-title">Network</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">Hostname:</span>
              <span class="info-value">{{ systemInfo.interfaces.hostname }}</span>
            </div>
            <div v-for="(ip, iface) in systemInfo.interfaces.interfaces" :key="iface" class="info-row">
              <span class="info-label">{{ iface }}:</span>
              <span class="info-value">{{ ip }}</span>
            </div>
          </div>
        </div>

        <!-- Storage Section -->
        <div class="system-card">
          <div class="card-header">
            <i class="fas fa-hdd icon-color"></i>
            <span class="header-title">Storage</span>
          </div>
          <div class="card-content">
            <div class="info-row">
              <span class="info-label">Total:</span>
              <span class="info-value">{{ systemInfo.disk.total.toFixed(1) }} GB</span>
            </div>
            <div class="info-row">
              <span class="info-label">Used:</span>
              <span class="info-value">{{ systemInfo.disk.used.toFixed(1) }} GB</span>
            </div>
            <div class="info-row">
              <span class="info-label">Available:</span>
              <span class="info-value">{{ systemInfo.disk.available.toFixed(1) }} GB</span>
            </div>
            <div class="disk-usage-container">
              <div class="progress-bar-container">
                <div class="progress-bar" :class="{ 'gauge-low': diskUsagePercentage > 80 }" :style="{ width: diskUsagePercentage + '%' }"></div>
              </div>
              <p class="progress-text">{{ diskUsagePercentage }}% Used</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Hostname Management Section -->
      <div class="hostname-section">
        <div class="section-header">
          <h2 class="section-title">Hostname Management</h2>
        </div>

        <div class="hostname-card">
          <div class="card-content">
            <p class="hostname-description">
              Change the hostname of this device. The change will take effect after rebooting the system.
            </p>

            <div class="hostname-form">
              <div class="hostname-input-container">
                <label for="new-hostname" class="hostname-label">New Hostname:</label>
                <input
                  id="new-hostname"
                  v-model="newHostname"
                  class="hostname-input"
                  placeholder="Enter new hostname"
                  pattern="[a-zA-Z0-9\-]+"
                  maxlength="63"
                />
                <small class="hostname-hint">Only alphanumeric characters and hyphens (-) are allowed. Max 63 characters.</small>
              </div>

              <div class="hostname-actions">
                <button
                  @click="changeHostname"
                  class="hostname-button"
                  :disabled="!isValidHostname || isChangingHostname"
                  :class="{'disabled': !isValidHostname || isChangingHostname}"
                >
                  <i v-if="isChangingHostname" class="fas fa-spinner fa-spin"></i>
                  <span v-else>Change Hostname</span>
                </button>
              </div>
            </div>

            <div v-if="hostnameMessage" class="hostname-message" :class="{'success': !hostnameError, 'error': hostnameError}">
              <i :class="hostnameError ? 'fas fa-exclamation-circle' : 'fas fa-check-circle'"></i>
              <span>{{ hostnameMessage }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Confirm Dialog -->
    <div v-if="showConfirmDialog" class="dialog-overlay">
      <div class="dialog-container">
        <div class="dialog-header">
          <h3 class="dialog-title">Confirm Hostname Change</h3>
          <button @click="showConfirmDialog = false" class="close-button">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="dialog-content">
          <div class="warning-icon">
            <i class="fas fa-exclamation-triangle"></i>
          </div>
          <p class="dialog-text">
            Are you sure you want to change the hostname from <strong>{{ systemInfo.interfaces.hostname }}</strong> to <strong>{{ newHostname }}</strong>?
          </p>
          <p class="dialog-text">
            A system reboot will be required for the change to take effect.
          </p>
          <div class="dialog-actions">
            <button @click="showConfirmDialog = false" class="cancel-button">Cancel</button>
            <button @click="confirmHostnameChange" class="confirm-button" :class="{'loading': isChangingHostname}">
              <i v-if="isChangingHostname" class="fas fa-spinner fa-spin"></i>
              <span v-else>Change Hostname</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import SystemService from '../services/SystemService';

export default {
  props: {
    initialSystemInfo: {
      type: Object,
      default: function() {
        return {
          hardware: {
            model: '',
            module: '',
            serial_number: '',
            l4t: '',
            jetpack: ''
          },
          platform: {
            distribution: '',
            release: '',
            python: ''
          },
          libraries: {
            cuda: '',
            opencv: '',
            opencv_cuda: false,
            cudnn: '',
            tensorrt: '',
            vpi: '',
            vulkan: ''
          },
          power: {
            nvpmodel: '',
            jetson_clocks: false,
            total: 0,
            temperature: {
              cpu: 0,
              gpu: 0,
              tj: 0
            }
          },
          interfaces: {
            hostname: '',
            interfaces: {}
          },
          disk: {
            total: 0,
            used: 0,
            available: 0
          }
        };
      }
    }
  },
  data() {
    return {
      systemInfo: {
        hardware: {
          model: '',
          module: '',
          serial_number: '',
          l4t: '',
          jetpack: ''
        },
        platform: {
          distribution: '',
          release: '',
          python: ''
        },
        libraries: {
          cuda: '',
          opencv: '',
          opencv_cuda: false,
          cudnn: '',
          tensorrt: '',
          vpi: '',
          vulkan: ''
        },
        power: {
          nvpmodel: '',
          jetson_clocks: false,
          total: 0,
          temperature: {
            cpu: 0,
            gpu: 0,
            tj: 0
          }
        },
        interfaces: {
          hostname: '',
          interfaces: {}
        },
        disk: {
          total: 0,
          used: 0,
          available: 0
        }
      },
      loading: true,
      pollingInterval: null,
      newHostname: '',
      hostnameMessage: '',
      hostnameError: false,
      isChangingHostname: false,
      showConfirmDialog: false
    };
  },
  computed: {
    diskUsagePercentage() {
      return Math.round((this.systemInfo.disk.used / this.systemInfo.disk.total) * 100);
    },
    isValidHostname() {
      // Hostname validation: alphanumeric characters and hyphens only
      // Must not start or end with a hyphen
      const hostnameRegex = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
      return this.newHostname && hostnameRegex.test(this.newHostname);
    }
  },
  mounted() {
    if (this.initialSystemInfo) {
      this.systemInfo = { ...this.initialSystemInfo };
      this.loading = false;
    }
    this.fetchSystemInfo();
    this.startPolling();
  },
  beforeUnmount() {
    this.stopPolling();
  },
  methods: {
    startPolling() {
      this.pollingInterval = setInterval(() => {
        this.fetchSystemInfo();
      }, 3000); // Poll every 3 seconds
    },
    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
      }
    },
    async fetchSystemInfo() {
      try {
        const response = await SystemService.getSystemInfo();
        if (response.data) {
          this.systemInfo = response.data;
          this.loading = false;
        }
      } catch (error) {
        console.error('Error fetching system information:', error);
        this.loading = false;
      }
    },
    changeHostname() {
      if (!this.isValidHostname) return;

      // Show confirmation dialog
      this.showConfirmDialog = true;
    },
    async confirmHostnameChange() {
      this.isChangingHostname = true;
      this.hostnameMessage = '';

      try {
        // Call the API to change hostname
        const response = await SystemService.changeHostname(this.newHostname);

        if (response.data && response.data.success) {
          this.hostnameMessage = response.data.message;
          this.hostnameError = false;
          this.newHostname = '';
        } else {
          throw new Error(response.data.message || 'Failed to change hostname');
        }
      } catch (error) {
        console.error('Error changing hostname:', error);
        this.hostnameMessage = `Error: ${error.response?.data?.message || error.message || 'Failed to change hostname'}`;
        this.hostnameError = true;
      } finally {
        this.isChangingHostname = false;
        this.showConfirmDialog = false;
      }
    }
  }
}
</script>

<style scoped>
/* Page Layout */
.page-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  gap: 20px;
  box-sizing: border-box;
}

.page-title {
  font-size: 1.8rem;
  font-weight: bold;
  color: var(--ark-color-black);
  margin: 0 0 16px 0;
  text-align: center;
}

.system-content {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* Loading Container */
.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  height: 200px;
  width: 100%;
}

.loading-container i {
  font-size: 2.5rem;
  color: var(--ark-color-blue);
  animation: spin 1s infinite linear;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* System Grid */
.system-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  grid-auto-rows: minmax(min-content, auto);
  gap: 16px;
  width: 100%;
}

.system-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  transition: box-shadow 0.2s ease;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.system-card:hover {
  box-shadow: 0 4px 12px var(--ark-color-black-shadow);
}

/* Card Headers */
.card-header {
  display: flex;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
  gap: 8px;
}

.header-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--ark-color-black);
}

.icon-color {
  color: var(--ark-color-black);
}

/* Card Content */
.card-content {
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

/* Info Rows */
.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label {
  font-weight: 500;
  color: var(--ark-color-black);
}

.info-value {
  color: var(--ark-color-black);
  text-align: right;
  max-width: 65%;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Progress Bar */
.disk-usage-container {
  margin-top: 8px;
}

.progress-bar-container {
  width: 100%;
  height: 8px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 4px;
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  background-color: var(--ark-color-green);
  border-radius: 4px;
  transition: width 0.3s ease;
}

.progress-bar.gauge-low {
  background-color: var(--ark-color-red);
}

.progress-text {
  font-size: 0.8rem;
  text-align: right;
  margin: 4px 0 0 0;
  color: var(--ark-color-black);
}

/* Hostname Management Section */
.hostname-section {
  width: 100%;
  margin-top: 20px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.section-title {
  font-size: 1.3rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
}

.hostname-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  padding: 20px;
  width: 100%;
  box-sizing: border-box;
}

.hostname-description {
  margin: 0 0 20px 0;
  color: var(--ark-color-black);
}

.hostname-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.hostname-input-container {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.hostname-label {
  font-weight: 500;
  color: var(--ark-color-black);
}

.hostname-input {
  padding: 10px 12px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
  font-size: 1rem;
}

.hostname-input:focus {
  outline: none;
  border-color: var(--ark-color-blue);
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.3);
}

.hostname-hint {
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.hostname-actions {
  display: flex;
  justify-content: flex-end;
}

.hostname-button {
  padding: 10px 20px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 160px;
}

.hostname-button:hover:not(.disabled) {
  background-color: var(--ark-color-green-hover);
}

.hostname-button.disabled {
  background-color: var(--ark-color-black-shadow);
  cursor: not-allowed;
  opacity: 0.7;
}

.hostname-message {
  margin-top: 16px;
  padding: 12px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.hostname-message.success {
  background-color: var(--ark-color-green-shadow);
  color: var(--ark-color-green);
}

.hostname-message.error {
  background-color: rgba(244, 67, 54, 0.1);
  color: var(--ark-color-red);
}

/* Confirm Dialog */
.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.dialog-container {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  width: 90%;
  max-width: 500px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
}

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.dialog-title {
  margin: 0;
  font-size: 1.2rem;
  font-weight: 600;
}

.close-button {
  background: none;
  border: none;
  font-size: 1.2rem;
  cursor: pointer;
}

.dialog-content {
  padding: 20px;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.warning-icon {
  font-size: 3rem;
  color: var(--ark-color-orange);
  margin-bottom: 16px;
}

.dialog-text {
  text-align: center;
  margin-bottom: 20px;
  line-height: 1.5;
}

.dialog-actions {
  display: flex;
  justify-content: center;
  gap: 16px;
  margin-top: 16px;
}

.cancel-button {
  padding: 8px 16px;
  background-color: var(--ark-color-black-shadow);
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.confirm-button {
  padding: 8px 16px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 140px;
}

.confirm-button:hover {
  background-color: rgba(52, 152, 219, 0.8);
}

.confirm-button.loading {
  opacity: 0.8;
  cursor: wait;
}

/* Responsive adjustments */
@media (max-width: 1200px) {
  .system-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .system-grid {
    grid-template-columns: 1fr;
  }

  .hostname-form {
    flex-direction: column;
  }

  .hostname-actions {
    justify-content: flex-start;
    margin-top: 16px;
  }
}
</style>
