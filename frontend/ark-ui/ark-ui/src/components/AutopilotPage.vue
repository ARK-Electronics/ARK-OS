<template>
  <div class="page-container">
    <!-- Header -->
    <h1 class="page-title">Autopilot Management</h1>

    <!-- Navigation Tabs -->
    <div class="tabs-container">
      <button
        class="tab-button"
        :class="{ 'active': activeSection === 'status' }"
        @click="activeSection = 'status'"
      >
        Status
      </button>
      <button
        class="tab-button"
        :class="{ 'active': activeSection === 'firmware' }"
        @click="activeSection = 'firmware'"
      >
        Firmware
      </button>
      <button
        class="tab-button"
        :class="{ 'active': activeSection === 'maintenance' }"
        @click="activeSection = 'maintenance'"
      >
        Tools
      </button>
      <!-- Placeholder for future extensions -->
      <button
        class="tab-button disabled"
        disabled
      >
        <i class="fas fa-tools"></i> Advanced
      </button>
    </div>

    <!-- Tab Content Wrapper -->
    <div class="tab-content-wrapper">
      <!-- Status Section -->
      <div v-if="activeSection === 'status'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">Autopilot Status</h2>
          <div class="header-actions">
            <button @click="fetchAutopilotData" class="refresh-button">
              <i class="fas fa-sync-alt" :class="{ 'fa-spin': isRefreshing }"></i>
              Refresh
            </button>
          </div>
        </div>

        <!-- Connection Status Banner -->
        <div class="connection-banner" :class="connectionBannerClass">
          <div class="banner-content">
            <i :class="connectionStatusIcon"></i>
            <span>{{ statusText }}</span>
          </div>
        </div>

        <!-- Autopilot Details -->
        <div class="status-cards">
          <!-- System Info Card -->
          <div class="status-card">
            <h3 class="card-title system-title">
              <i class="fas fa-microchip"></i> System Information
            </h3>
            <div class="info-grid">
              <div class="info-item">
                <span class="info-label">Autopilot Type:</span>
                <span class="info-value">{{ autopilot.autopilot_type }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Version:</span>
                <span class="info-value">{{ autopilot.version }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Git Hash:</span>
                <span class="info-value monospace">{{ autopilot.git_hash }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Last Heartbeat:</span>
                <span class="info-value">{{ formatHeartbeatTime(autopilot.last_heartbeat) }}</span>
              </div>
            </div>
          </div>

          <!-- Power Status Card -->
          <div class="status-card">
            <h3 class="card-title power-title">
              <i class="fas fa-bolt"></i> Power Status
            </h3>
            <div class="power-grid">
              <!-- Voltage -->
              <div class="power-item">
                <div class="power-gauge">
                  <div class="gauge-value">{{ formatNumber(autopilot.voltage, 2) }}</div>
                  <div class="gauge-unit">V</div>
                </div>
                <div class="gauge-label">Voltage</div>
                <div class="gauge-bar-container">
                  <div class="gauge-bar" :style="{ width: getVoltagePercentage() + '%' }"
                       :class="getVoltageClass()"></div>
                </div>
              </div>

              <!-- Current -->
              <div class="power-item">
                <div class="power-gauge">
                  <div class="gauge-value">{{ formatNumber(autopilot.current, 2) }}</div>
                  <div class="gauge-unit">A</div>
                </div>
                <div class="gauge-label">Current</div>
                <div class="gauge-bar-container">
                  <div class="gauge-bar" :style="{ width: getCurrentPercentage() + '%' }"
                       :class="getCurrentClass()"></div>
                </div>
              </div>

              <!-- Battery Percentage -->
              <div class="power-item">
                <div class="battery-indicator">
                  <div class="battery-percentage">{{ formatNumber(autopilot.remaining, 0) }}%</div>
                  <div class="battery-icon">
                    <i :class="getBatteryIcon()"></i>
                  </div>
                </div>
                <div class="gauge-label">Remaining</div>
                <div class="gauge-bar-container">
                  <div class="gauge-bar" :style="{ width: autopilot.remaining + '%' }"
                       :class="getBatteryClass()"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Firmware Section -->
      <div v-if="activeSection === 'firmware'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">Firmware Update</h2>
        </div>

        <!-- Current Version Card -->
        <div class="firmware-current-card">
          <div class="current-version-info">
            <div class="version-header">Current Version</div>
            <div class="version-details">
              <div class="version-item">
                <span class="version-label">Type:</span>
                <span class="version-value">{{ autopilot.autopilot_type }}</span>
              </div>
              <div class="version-item">
                <span class="version-label">Version:</span>
                <span class="version-value">{{ autopilot.version }}</span>
              </div>
              <div class="version-item">
                <span class="version-label">Git Hash:</span>
                <span class="version-value monospace">{{ autopilot.git_hash }}</span>
              </div>
            </div>
          </div>
          <div class="connection-status">
            <div class="status-indicator" :class="connectionStatusClass">
              <i :class="connectionStatusIcon"></i>
              <span>{{ statusText }}</span>
            </div>
          </div>
        </div>

        <!-- Upload Firmware Card -->
        <div class="firmware-upload-card">
          <h3 class="card-title upload-title">
            <i class="fas fa-upload"></i> Upload New Firmware
          </h3>

          <div class="file-upload-wrapper"
               @dragover.prevent="dragOverHandler"
               @drop.prevent="dropHandler"
               @dragleave.prevent="dragLeaveHandler">
            <input type="file" @change="handleFileUpload" class="file-input" accept=".apj,.px4"/>
            <div class="file-upload-content">
              <i class="fas fa-file-upload"></i>
              <div class="upload-text">
                <div class="primary-text">
                  {{ file ? file.name : 'Drag and drop or select a file' }}
                </div>
                <div class="secondary-text">
                  {{ file ? `${formatFileSize(file.size)}` : 'Supported formats: .apj, .px4' }}
                </div>
              </div>
              <button class="file-select-btn">Browse Files</button>
            </div>
          </div>

          <div v-if="isUploading" class="upload-progress-container">
            <div class="progress-info">
              <span class="progress-status">{{ statusMessage }}</span>
              <span class="progress-percentage">{{ progress.toFixed(1) }}%</span>
            </div>
            <div class="progress-bar-container">
              <div class="progress-bar" :style="{ width: `${progress}%` }"></div>
            </div>
          </div>

          <div v-if="statusMessage && !isUploading" class="upload-status"
               :class="{'status-error': uploadError, 'status-success': !uploadError}">
            <i :class="uploadError ? 'fas fa-exclamation-circle' : 'fas fa-check-circle'"></i>
            <span>{{ statusMessage }}</span>
          </div>

          <div class="upload-actions">
            <button @click="uploadFirmware"
                    class="upload-btn"
                    :disabled="!file || (!isConnected && !isInBootloader) || isUploading"
                    :class="{'disabled': !file || (!isConnected && !isInBootloader) || isUploading}">
              <i class="fas fa-upload"></i> Upload Firmware
            </button>
          </div>
        </div>
      </div>

      <!-- Maintenance Section -->
      <div v-if="activeSection === 'maintenance'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">Maintenance Tools</h2>
        </div>

        <div class="maintenance-grid">

          <!-- Reset Flight Controller Card -->
          <div class="maintenance-card">
            <div class="maintenance-icon">
              <i class="fas fa-redo-alt"></i>
            </div>
            <div class="maintenance-content">
              <h3 class="maintenance-title">Reset Flight Controller</h3>
              <p class="maintenance-description">
                Restart the flight controller to resolve minor issues or apply settings changes.
              </p>
              <div class="maintenance-actions">
                <button @click="showResetConfirmation = true"
                        class="maintenance-button"
                        :disabled="!isConnected && !isInBootloader"
                        :class="{'disabled': !isConnected && !isInBootloader}">
                  Reset Controller
                </button>
              </div>
            </div>
          </div>

          <!-- Calibration Card -->
          <div class="maintenance-card">
            <div class="maintenance-icon">
              <i class="fas fa-compass"></i>
            </div>
            <div class="maintenance-content">
              <h3 class="maintenance-title">Sensor Calibration</h3>
              <p class="maintenance-description">
                Calibrate sensors such as compass, accelerometer, or gyroscope.
              </p>
              <div class="maintenance-actions">
                <button class="maintenance-button disabled" disabled>
                  Coming Soon
                </button>
              </div>
            </div>
          </div>

          <!-- Parameter Reset Card -->
          <div class="maintenance-card">
            <div class="maintenance-icon">
              <i class="fas fa-sliders-h"></i>
            </div>
            <div class="maintenance-content">
              <h3 class="maintenance-title">Reset Parameters</h3>
              <p class="maintenance-description">
                Reset all parameters to default factory settings.
              </p>
              <div class="maintenance-actions">
                <button class="maintenance-button disabled" disabled>
                  Coming Soon
                </button>
              </div>
            </div>
          </div>

          <!-- Log Files Card -->
          <div class="maintenance-card">
            <div class="maintenance-icon">
              <i class="fas fa-file-alt"></i>
            </div>
            <div class="maintenance-content">
              <h3 class="maintenance-title">Log File Management</h3>
              <p class="maintenance-description">
                Download, view, or delete onboard log files from the autopilot.
              </p>
              <div class="maintenance-actions">
                <button class="maintenance-button disabled" disabled>
                  Coming Soon
                </button>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <!-- Reset Confirmation Dialog -->
    <div v-if="showResetConfirmation" class="dialog-overlay">
      <div class="dialog-container">
        <div v-if="!isResetting">
          <!-- Pre-reset confirmation view -->
          <div class="dialog-header">
            <h3 class="dialog-title">Reset Flight Controller</h3>
            <button @click="showResetConfirmation = false" class="close-button">
              <i class="fas fa-times"></i>
            </button>
          </div>
          <div class="dialog-content">
            <div class="warning-icon">
              <i class="fas fa-exclamation-triangle"></i>
            </div>
            <p class="dialog-text">
              Are you sure you want to reset the flight controller?
            </p>
            <div class="reset-options">
              <div class="reset-option">
                <input type="radio" id="reset-normal" v-model="resetMode" value="normal">
                <label for="reset-normal">Normal Reset</label>
                <p class="reset-description">Standard restart of the autopilot.</p>
              </div>
              <div class="reset-option">
                <input type="radio" id="reset-bootloader" v-model="resetMode" value="bootloader">
                <label for="reset-bootloader">Bootloader</label>
                <p class="reset-description">Reset to bootloader (use only for firmware updates).</p>
              </div>
            </div>
            <div class="dialog-actions">
              <button @click="showResetConfirmation = false" class="cancel-button">Cancel</button>
              <button @click="resetFlightController" class="confirm-button">
                Reset Controller
              </button>
            </div>
          </div>
        </div>

        <!-- Reset in progress view -->
        <div v-else class="dialog-content loading-content">
          <div class="reset-spinner">
            <i class="fas fa-spinner fa-spin"></i>
          </div>
          <h3 class="loading-title">Resetting Flight Controller</h3>
          <p class="loading-text">
            Please wait while the controller restarts...
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import io from 'socket.io-client';
import AutopilotService from '../services/AutopilotService';

export default {
  data() {
    return {
      activeSection: 'status',
      isRefreshing: false,
      autopilot: {
        autopilot_type: '--',
        version: '--',
        git_hash: '--',
        voltage: 0,
        remaining: 0,
        current: 0,
        connected: false,
        in_bootloader: false,
        last_heartbeat: null
      },
      file: null,
      progress: 0,
      statusMessage: '',
      uploadError: false,
      socket: null,
      isUploading: false,
      pollingInterval: null,
      showResetConfirmation: false,
      resetMode: 'normal',
      isResetting: false
    };
  },
  computed: {
    isConnected() {
      return this.autopilot.connected;
    },
    isInBootloader() {
      return this.autopilot.in_bootloader;
    },
    statusText() {
      if (this.isConnected) return 'Connected';
      if (this.isInBootloader) return 'Bootloader';
      return 'Disconnected';
    },
    connectionStatusIcon() {
      if (this.isConnected) return 'fas fa-check-circle';
      if (this.isInBootloader) return 'fas fa-microchip';
      return 'fas fa-exclamation-triangle';
    },
    connectionStatusClass() {
      if (this.isConnected) return 'connected';
      if (this.isInBootloader) return 'bootloader';
      return 'disconnected';
    },
    connectionBannerClass() {
      if (this.isConnected) return 'connected';
      if (this.isInBootloader) return 'bootloader';
      return 'disconnected';
    }
  },
  mounted() {
    this.connectSocket();
    this.fetchAutopilotData();
    this.startPolling();
  },
  beforeUnmount() {
    this.stopPolling();
    if (this.socket) {
      this.socket.disconnect();
    }
  },
  methods: {
    connectSocket() {
      // Connect to the firmware update socket
      this.socket = io(process.env.VUE_APP_SOCKET_URL || window.location.origin, {
        path: '/socket.io/autopilot-firmware-upload',
        transports: ['websocket'],
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
      });

      this.socket.on('connect', () => {
        console.log(`Connected to firmware update socket with ID: ${this.socket.id}`);
      });

      this.socket.on('progress', data => {
        this.progress = data.percent;
        this.statusMessage = `${data.status} ${data.percent.toFixed(2)}%`;
        this.isUploading = true;
        this.uploadError = false;
      });

      this.socket.on('completed', message => {
        this.statusMessage = message.message;
        this.isUploading = false;
        this.uploadError = false;

        // Refresh autopilot data after firmware update
        setTimeout(() => this.fetchAutopilotData(), 3000);
      });

      this.socket.on('error', error => {
        this.statusMessage = `Error: ${error.message || error}`;
        console.error('Error:', error);
        this.isUploading = false;
        this.uploadError = true;
      });
    },
    startPolling() {
      this.pollingInterval = setInterval(() => {
        this.fetchAutopilotData();
      }, 1000); // Poll every 1 second
    },
    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
      }
    },
    async fetchAutopilotData() {
      this.isRefreshing = true;
      try {
        const response = await AutopilotService.getAutopilotDetails();
        this.autopilot = response.data;
      } catch (error) {
        console.error('Error fetching autopilot data:', error);
        this.autopilot.connected = false;
        this.autopilot.in_bootloader = false;
      } finally {
        this.isRefreshing = false;
      }
    },
    handleFileUpload(event) {
      this.file = event.target.files[0];
      this.statusMessage = '';
      this.uploadError = false;
    },
    dragOverHandler(event) {
      event.currentTarget.style.background = 'var(--ark-color-black-shadow)';
    },
    dragLeaveHandler(event) {
      event.currentTarget.style.background = 'none';
    },
    dropHandler(event) {
      this.file = event.dataTransfer.files[0];
      this.handleFileUpload({ target: { files: event.dataTransfer.files } });
    },
    async uploadFirmware() {
      if (!this.file || (!this.isConnected && !this.isInBootloader)) return;

      this.isUploading = true;
      this.progress = 0;
      this.statusMessage = 'Preparing firmware upload...';
      this.uploadError = false;

      const formData = new FormData();
      formData.append('firmware', this.file);
      formData.append('socketId', this.socket.id);

      try {
        const response = await AutopilotService.uploadFirmware(formData);
        this.statusMessage = response.data.message;
        this.uploadError = false;
      } catch (error) {
        console.error('Upload failed', error.response ? error.response.data : error);
        this.statusMessage = `Upload failed: ${error.response ? error.response.data : error.message}`;
        this.isUploading = false;
        this.uploadError = true;
      }
    },
    formatNumber(value, decimals = 0) {
      if (value === undefined || value === null || isNaN(value)) return '--';
      return Number(value).toFixed(decimals);
    },
    formatFileSize(bytes) {
      if (bytes === 0) return '0 Bytes';

      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));

      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    formatHeartbeatTime(timestamp) {
      if (!timestamp) return 'Never';

      try {
        const heartbeatTime = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - heartbeatTime) / 1000); // difference in seconds

        if (diff < 10) return 'Just now';
        if (diff < 60) return `${diff} seconds ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;

        return heartbeatTime.toLocaleTimeString();
      } catch (e) {
        return 'Unknown';
      }
    },
    getVoltagePercentage() {
      // Assuming normal voltage range is 10-13V, scale to percentage
      const minVoltage = 10;
      const maxVoltage = 13;
      const voltage = this.autopilot.voltage;

      if (voltage <= minVoltage) return 0;
      if (voltage >= maxVoltage) return 100;

      return ((voltage - minVoltage) / (maxVoltage - minVoltage)) * 100;
    },
    getVoltageClass() {
      const voltage = this.autopilot.voltage;
      if (voltage >= 12) return 'gauge-high';
      if (voltage >= 11) return 'gauge-medium';
      return 'gauge-low';
    },
    getCurrentPercentage() {
      // Scale current as percentage of 30A max
      const maxCurrent = 30;
      const current = Math.abs(this.autopilot.current);

      return Math.min((current / maxCurrent) * 100, 100);
    },
    getCurrentClass() {
      const current = Math.abs(this.autopilot.current);
      if (current < 5) return 'gauge-low';
      if (current < 15) return 'gauge-medium';
      return 'gauge-high';
    },
    getBatteryIcon() {
      const remaining = this.autopilot.remaining;

      if (remaining >= 75) return 'fas fa-battery-full';
      if (remaining >= 50) return 'fas fa-battery-three-quarters';
      if (remaining >= 25) return 'fas fa-battery-half';
      if (remaining >= 10) return 'fas fa-battery-quarter';
      return 'fas fa-battery-empty';
    },
    getBatteryClass() {
      const remaining = this.autopilot.remaining;

      if (remaining >= 50) return 'gauge-high';
      if (remaining >= 20) return 'gauge-medium';
      return 'gauge-low';
    },
    async resetFlightController() {
      // Set resetting state to true - this will show the loading screen
      this.isResetting = true;

      try {
        // Determine which reset method to use based on reset mode
        let response;
        if (this.resetMode === 'bootloader') {
          response = await AutopilotService.resetFmuBootloader();
        } else {
          response = await AutopilotService.resetFmu();
        }

        if (response.data.success) {
          // Success! The reset command was sent successfully
          this.statusMessage = 'Flight controller reset successfully.';
          this.uploadError = false;

          // First wait for the controller to start restarting
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Start polling for reconnection
          const waitForReconnection = async () => {
            // Time to wait between polls
            const pollInterval = 1000; // 1 second
            // Maximum time to wait for reconnection
            const maxWaitTime = 20000; // 20 seconds
            // Total time waited so far
            let timeWaited = 0;

            while (timeWaited < maxWaitTime) {
              // Try to fetch autopilot data
              await this.fetchAutopilotData();

              // If we're connected or in bootloader, we're done
              if (this.isConnected || this.isInBootloader) {
                // Wait a moment to ensure we're stable
                await new Promise(resolve => setTimeout(resolve, 1000));
                return true;
              }

              // Wait for the next check
              await new Promise(resolve => setTimeout(resolve, pollInterval));
              timeWaited += pollInterval;
            }

            // If we get here, we timed out
            return false;
          };

          // Wait for reconnection
          const reconnected = await waitForReconnection();

          if (!reconnected) {
            // We timed out waiting for reconnection
            console.warn('Timed out waiting for autopilot to reconnect');
            this.statusMessage = 'Reset initiated, but reconnection timed out. Please check device status.';
          }

          // Close the dialog regardless of outcome
          this.isResetting = false;
          this.showResetConfirmation = false;
        } else {
          throw new Error(response.data.message || 'Reset failed');
        }
      } catch (error) {
        console.error('Reset failed:', error);
        this.statusMessage = `Reset failed: ${error.message}`;
        this.uploadError = true;
        this.isResetting = false;
      }
    }
  }
};
</script>

<style scoped>
/* Page Layout */
.page-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 1200px;
  min-width: 800px;
  margin: 0 auto;
  padding: 20px;
  gap: 20px;
  position: relative;
  box-sizing: border-box;
  overflow-x: hidden;
  height: 100%;
  max-height: 100vh;
}

.page-title {
  font-size: 1.8rem;
  font-weight: bold;
  color: var(--ark-color-black);
  margin: 0 0 16px 0;
  text-align: center;
}

/* Navigation Tabs */
.tabs-container {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  width: 100%;
  margin-bottom: 16px;
  position: sticky;
  top: 0;
  z-index: 100;
  background-color: var(--ark-color-white);
  padding: 8px 0;
  box-sizing: border-box;
  min-width: 100%; /* Critical: prevents width changes */
}

.tab-button {
  padding: 12px;
  background-color: var(--ark-color-white);
  border: none;
  border-radius: 8px;
  color: var(--ark-color-black);
  font-weight: 500;
  transition: background-color 0.2s, color 0.2s;
  cursor: pointer;
  box-shadow: 0 2px 4px var(--ark-color-black-shadow);
  white-space: nowrap;
  text-overflow: ellipsis;
  overflow: hidden;
  text-align: center;
  box-sizing: border-box;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
}

.tab-button:hover {
  background-color: var(--ark-color-black-shadow);
}

.tab-button.active {
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
}

.tab-button.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Tab Content Container */
.tab-content-wrapper {
  width: 100%;
  min-width: 100%;
  max-width: 100%;
  position: relative;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  overflow: hidden; /* Prevents expansion */
}

.section-container {
  width: 100%;
  min-width: 100%;
  max-width: 100%;
  transition: opacity 0.2s ease;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  background-color: var(--ark-color-white);
  border-radius: 8px;
  padding: 20px;
  box-sizing: border-box;
  overflow: hidden; /* Critical: prevents horizontal scrolling */
  display: flex;
  flex-direction: column;
  position: relative;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.section-title {
  font-size: 1.3rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
}

.header-actions {
  display: flex;
  background: none;
  padding: 0;
  gap: 10px;
  align-items: center;
}

.refresh-button {
  display: flex;
  align-items: center;
  gap: 6px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  padding: 8px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background-color 0.2s;
}

.refresh-button:hover {
  background-color: rgba(52, 152, 219, 0.8);
}

.fa-spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Connection Banner */
.connection-banner {
  width: 100%;
  padding: 12px;
  border-radius: 8px;
  margin-bottom: 20px;
  box-sizing: border-box;
  transition: all 0.3s ease;
}

.connection-banner.connected {
  background-color: var(--ark-color-green-shadow);
  border: 1px solid var(--ark-color-green);
}

.connection-banner.disconnected {
  background-color: rgba(244, 67, 54, 0.1);
  border: 1px solid var(--ark-color-red);
}

.connection-banner.bootloader {
  background-color: rgba(52, 152, 219, 0.1);
  border: 1px solid var(--ark-color-blue);
}

.banner-content {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-weight: 500;
}

.connected .banner-content {
  color: var(--ark-color-green);
}

.disconnected .banner-content {
  color: var(--ark-color-red);
}

.bootloader .banner-content {
  color: var(--ark-color-blue);
}

/* Status Cards Layout */
.status-cards {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
  margin-bottom: 20px;
  width: 100%;
}

.status-card,
.firmware-current-card,
.firmware-upload-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  padding: 16px;
  transition: all 0.2s ease;
  width: 100%;
  box-sizing: border-box;
}

.card-title {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 16px 0;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.system-title {
  color: var(--ark-color-blue);
}

.power-title {
  color: var(--ark-color-orange);
}

.upload-title {
  color: var(--ark-color-blue);
}

/* Info Grid for System Info */
.info-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.info-value {
  font-weight: 500;
}

/* Power Status Card */
.power-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.power-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.power-gauge {
  display: flex;
  align-items: baseline;
  gap: 4px;
}

.gauge-value {
  font-size: 1.8rem;
  font-weight: 600;
}

.gauge-unit {
  font-size: 1rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.gauge-label {
  font-size: 0.9rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.gauge-bar-container {
  width: 100%;
  height: 8px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 4px;
  overflow: hidden;
}

.gauge-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease;
}

.gauge-low {
  background-color: var(--ark-color-red);
}

.gauge-medium {
  background-color: var(--ark-color-orange);
}

.gauge-high {
  background-color: var(--ark-color-green);
}

.battery-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
}

.battery-percentage {
  font-size: 1.8rem;
  font-weight: 600;
}

.battery-icon {
  font-size: 1.5rem;
  display: flex;
  align-items: center;
}

/* Firmware Section */
.firmware-current-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 16px;
}

.current-version-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.version-header {
  font-weight: 600;
  font-size: 1.1rem;
  color: var(--ark-color-black);
}

.version-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}

.version-item {
  display: flex;
  gap: 8px;
}

.version-label {
  color: var(--ark-color-black);
  opacity: 0.7;
}

.version-value {
  font-weight: 500;
}

.connection-status {
  display: flex;
  align-items: center;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 20px;
  font-weight: 500;
}

.status-indicator.connected {
  background-color: var(--ark-color-green-shadow);
  color: var(--ark-color-green);
}

.status-indicator.disconnected {
  background-color: rgba(244, 67, 54, 0.1);
  color: var(--ark-color-red);
}

.status-indicator.bootloader {
  background-color: rgba(52, 152, 219, 0.1);
  color: var(--ark-color-blue);
}

/* Firmware Upload */
.firmware-upload-card {
  padding: 20px;
  margin-bottom: 20px;
}

.file-upload-wrapper {
  position: relative;
  border: 2px dashed var(--ark-color-black-shadow);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  text-align: center;
  transition: all 0.2s ease;
}

.file-upload-wrapper:hover {
  border-color: var(--ark-color-blue);
  background-color: rgba(52, 152, 219, 0.05);
}

.file-input {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0;
  cursor: pointer;
}

.file-upload-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.file-upload-content i {
  font-size: 2.5rem;
  color: var(--ark-color-black);
  opacity: 0.5;
}

.upload-text {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.primary-text {
  font-size: 1rem;
  font-weight: 500;
}

.secondary-text {
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.file-select-btn {
  padding: 8px 16px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.file-select-btn:hover {
  background-color: rgba(52, 152, 219, 0.8);
}

.upload-progress-container {
  margin-bottom: 16px;
}

.progress-info {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.progress-status {
  font-size: 0.9rem;
}

.progress-percentage {
  font-weight: 500;
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

.upload-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-radius: 4px;
  margin-bottom: 16px;
}

.status-success {
  background-color: var(--ark-color-green-shadow);
  color: var(--ark-color-green);
}

.status-error {
  background-color: rgba(244, 67, 54, 0.1);
  color: var(--ark-color-red);
}

.upload-actions {
  display: flex;
  justify-content: flex-end;
}

.upload-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
}

.upload-btn:hover:not(.disabled) {
  background-color: var(--ark-color-green-hover);
}

.upload-btn.disabled {
  background-color: var(--ark-color-black-shadow);
  cursor: not-allowed;
  opacity: 0.7;
}

.monospace {
  font-family: monospace;
}

/* Maintenance Section - Fixed to prevent layout expansion */
.maintenance-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr)); /* Critical for preventing expansion */
  gap: 20px;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  overflow: hidden;
}

.maintenance-card {
  display: flex;
  width: 100%;
  max-width: 100%;
  min-width: 0;
  box-sizing: border-box;
  overflow: hidden;
  padding: 20px;
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  transition: box-shadow 0.2s ease;
}

.maintenance-card:hover {
  box-shadow: 0 4px 12px var(--ark-color-black-shadow);
}

.maintenance-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2rem;
  width: 60px;
  min-width: 60px;
  margin-right: 16px;
  color: var(--ark-color-blue);
  flex-shrink: 0;
}

.maintenance-content {
  flex: 1;
  min-width: 0; /* Critical to allow content to shrink */
  max-width: 100%;
  display: flex;
  flex-direction: column;
  gap: 8px;
  overflow: hidden;
  word-break: break-word;
}

.maintenance-title {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0;
  color: var(--ark-color-black);
  max-width: 100%;
  overflow-wrap: break-word;
}

.maintenance-description {
  margin: 0;
  font-size: 0.9rem;
  color: var(--ark-color-black);
  opacity: 0.8;
  line-height: 1.4;
  max-width: 100%;
  overflow-wrap: break-word;
  word-wrap: break-word;
}

.maintenance-actions {
  margin-top: 12px;
}

.maintenance-button {
  padding: 8px 16px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.maintenance-button:hover:not(.disabled) {
  background-color: rgba(52, 152, 219, 0.8);
}

.maintenance-button.disabled {
  background-color: var(--ark-color-black-shadow);
  cursor: not-allowed;
  opacity: 0.7;
}

/* Reset Confirmation Dialog */
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

.reset-options {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 20px;
}

.reset-option {
  display: flex;
  flex-direction: column;
  padding: 12px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 8px;
  transition: all 0.2s ease;
}

.reset-option:hover {
  background-color: var(--ark-color-light-grey);
}

.reset-option input {
  margin-right: 8px;
}

.reset-option label {
  font-weight: 500;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.reset-description {
  margin: 4px 0 0 24px;
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
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
  background-color: var(--ark-color-red);
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
  background-color: rgba(244, 67, 54, 0.8);
}

.confirm-button.loading {
  opacity: 0.8;
  cursor: wait;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .status-cards,
  .maintenance-grid {
    grid-template-columns: 1fr;
  }

  .power-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .firmware-current-card {
    flex-direction: column;
    gap: 16px;
    align-items: flex-start;
  }

  .version-details {
    flex-direction: column;
    gap: 8px;
  }

  .connection-status {
    align-self: center;
  }
}

/* Reset Status Message Styles */
.reset-status {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  margin: 16px 0;
  padding: 16px;
  background-color: rgba(52, 152, 219, 0.1);
  border-radius: 8px;
  width: 100%;
}

.reset-spinner {
  font-size: 2rem;
  color: var(--ark-color-blue);
}

.reset-message {
  font-size: 1rem;
  font-weight: 500;
  color: var(--ark-color-blue);
  text-align: center;
}

/* Disabled controls during reset */
.dialog-container button:disabled,
.reset-options input:disabled,
.reset-options input:disabled + label {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Reset Loading State Styles */
.loading-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 20px;
  text-align: center;
}

.reset-spinner {
  font-size: 3rem;
  color: var(--ark-color-blue);
  margin-bottom: 24px;
}

.loading-title {
  font-size: 1.2rem;
  font-weight: 600;
  margin: 0 0 12px 0;
  color: var(--ark-color-black);
}

.loading-text {
  font-size: 1rem;
  color: var(--ark-color-black);
  opacity: 0.8;
  margin: 0;
}

/* Animation for the spinner */
@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.fa-spin {
  animation: spin 1.2s linear infinite;
}

</style>
