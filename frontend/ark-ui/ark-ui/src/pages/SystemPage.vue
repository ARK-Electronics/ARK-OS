<template>
  <div class="page-container">
    <h1 class="page-title">System Information</h1>

    <div v-if="loading" class="loading-container">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Loading system information...</p>
    </div>

    <div v-else-if="error" class="error-container">
      <i class="fas fa-exclamation-triangle"></i>
      <h2>Unable to Load System Information</h2>
      <p>{{ error }}</p>
      <button @click="retry" class="retry-button">
        <i class="fas fa-refresh"></i> Retry
      </button>
    </div>

    <div v-else class="system-content">
      <!-- System Cards Grid -->
      <div class="system-grid">
        <!-- Hardware Card -->
        <SystemCard
          title="Hardware"
          icon="fa-microchip"
          :data="hardwareData"
        />

        <!-- Platform Card -->
        <SystemCard
          title="Platform"
          icon="fa-server"
          :data="platformData"
        />

        <!-- Libraries Card -->
        <SystemCard
          title="Libraries"
          icon="fa-book"
          :data="librariesData"
        />

        <!-- Power & Temperature Card -->
        <SystemCard
          title="Power & Temperature"
          icon="fa-bolt"
          :data="powerTempData"
        >
          <template v-if="hasTemperatureData" #footer>
            <div class="temp-scroll-container">
              <div
                v-for="(temp, key) in allTemperatures"
                :key="key"
                class="temp-item"
              >
                <span class="temp-label">{{ formatTempLabel(key) }}:</span>
                <span class="temp-value">{{ temp.toFixed(1) }}°C</span>
              </div>
            </div>
          </template>
        </SystemCard>

        <!-- Network Card -->
        <SystemCard
          title="Network"
          icon="fa-network-wired"
          :data="networkData"
        />

        <!-- Memory Card -->
        <SystemCard
          title="Memory"
          icon="fa-memory"
          :data="memoryData"
        >
          <template v-if="hasMemoryData" #footer>
            <div class="memory-bars">
              <ProgressBar
                label="RAM"
                :value="ramPercent"
                :showPercentage="true"
              />
              <ProgressBar
                label="Disk"
                :value="diskPercent"
                :showPercentage="true"
                :warningThreshold="80"
                :criticalThreshold="90"
              />
            </div>
          </template>
        </SystemCard>
      </div>

      <!-- Hostname Management -->
      <HostnameManager
        :currentHostname="currentHostname"
        @hostnameChanged="onHostnameChanged"
      />
    </div>
  </div>
</template>

<script>
import SystemService from '@/services/SystemService';
import SystemCard from './components/SystemCard.vue';
import ProgressBar from './components/ProgressBar.vue';
import HostnameManager from './components/HostnameManager.vue';

export default {
  name: 'SystemPage',
  components: {
    SystemCard,
    ProgressBar,
    HostnameManager
  },
  data() {
    return {
      loading: true,
      error: null,
      systemInfo: null,
      pollingInterval: null,
      retryCount: 0,
      maxRetries: 3
    };
  },
  computed: {
    currentHostname() {
      // Check multiple possible locations for hostname
      return this.systemInfo?.network?.hostname ||
             this.systemInfo?.interfaces?.hostname ||
             'Unknown';
    },

    hardwareData() {
      const hw = this.systemInfo?.hardware;
      if (!hw) return { 'Status': 'Data unavailable' };

      return {
        'Model': hw.model || 'Not available',
        'Module': hw.module || 'Not available',
        'Serial': hw.serial_number || 'Not available',
        'L4T': hw.l4t || 'Not available',
        'JetPack': hw.jetpack || 'Not available'
      };
    },

    platformData() {
      const platform = this.systemInfo?.platform;
      if (!platform) return { 'Status': 'Data unavailable' };

      return {
        'Distribution': platform.distribution || 'Not available',
        'Release': platform.release || 'Not available',
        'Kernel': platform.kernel || 'Not available',
        'Architecture': platform.architecture || 'Not available',
        'Python': platform.python || 'Not available'
      };
    },

    librariesData() {
      const libs = this.systemInfo?.libraries;

      // Always show these fields, even if not available
      return {
        'CUDA': libs?.cuda || 'Not available',
        'OpenCV': libs?.opencv || 'Not available',
        'OpenCV-CUDA': libs?.opencv_cuda ? 'Enabled' : 'Not available',
        'cuDNN': libs?.cudnn || 'Not available',
        'TensorRT': libs?.tensorrt || 'Not available',
        'VPI': libs?.vpi || 'Not available',
        'Vulkan': libs?.vulkan || 'Not available'
      };
    },

    powerTempData() {
      const data = {};
      const power = this.systemInfo?.power;

      // Power information (primarily for Jetson)
      data['Power Mode'] = power?.nvpmodel || 'Not available';
      data['Jetson Clocks'] = power?.jetson_clocks ? 'Enabled' : 'Not available';
      data['Power Draw'] = power?.total ? `${(power.total / 1000).toFixed(2)} W` : 'Not available';

      // Primary temperatures
      const temps = this.systemInfo?.temperature || power?.temperature;
      if (temps) {
        data['CPU Temp'] = temps.cpu ? `${temps.cpu.toFixed(1)}°C` : 'Not available';
        data['GPU Temp'] = temps.gpu ? `${temps.gpu.toFixed(1)}°C` : 'Not available';
      } else {
        data['CPU Temp'] = 'Not available';
        data['GPU Temp'] = 'Not available';
      }

      return data;
    },

    allTemperatures() {
      // Get all temperature data for the scrollable list
      const temps = this.systemInfo?.temperature || this.systemInfo?.power?.temperature;
      if (!temps || temps.message) return {};

      const result = {};
      Object.entries(temps).forEach(([key, value]) => {
        if (typeof value === 'number' && value > 0) {
          result[key] = value;
        }
      });

      return result;
    },

    hasTemperatureData() {
      return Object.keys(this.allTemperatures).length > 2; // Show scroll if more than CPU/GPU
    },

    networkData() {
      const network = this.systemInfo?.network || this.systemInfo?.interfaces;
      if (!network) return { 'Status': 'Data unavailable' };

      const data = {
        'Hostname': network.hostname || 'Unknown'
      };

      const interfaces = network.interfaces || {};
      Object.entries(interfaces).forEach(([iface, ip]) => {
        data[iface] = ip;
      });

      return data;
    },

    memoryData() {
      const memory = this.systemInfo?.resources?.memory;
      const disk = this.systemInfo?.resources?.disk || this.systemInfo?.disk;

      const data = {};

      // RAM info
      if (memory) {
        data['Total RAM'] = `${memory.total.toFixed(1)} GB`;
        data['Available RAM'] = `${memory.available.toFixed(1)} GB`;
      } else {
        data['Total RAM'] = 'Not available';
        data['Available RAM'] = 'Not available';
      }

      // Disk info
      if (disk) {
        data['Total Disk'] = `${disk.total.toFixed(1)} GB`;
        data['Available Disk'] = `${disk.available.toFixed(1)} GB`;
      } else {
        data['Total Disk'] = 'Not available';
        data['Available Disk'] = 'Not available';
      }

      return data;
    },

    hasMemoryData() {
      const memory = this.systemInfo?.resources?.memory;
      const disk = this.systemInfo?.resources?.disk || this.systemInfo?.disk;
      return !!(memory || disk);
    },

    ramPercent() {
      return this.systemInfo?.resources?.memory?.percent || 0;
    },

    diskPercent() {
      const disk = this.systemInfo?.resources?.disk || this.systemInfo?.disk;
      return disk?.percent || 0;
    }
  },

  mounted() {
    this.fetchSystemInfo();
  },

  beforeUnmount() {
    this.stopPolling();
  },

  methods: {
    async fetchSystemInfo() {
      this.loading = true;
      this.error = null;

      try {
        const response = await SystemService.getSystemInfo();

        if (response.data) {
          this.systemInfo = response.data;
          this.loading = false;
          this.retryCount = 0;

          // Start polling after first successful load
          if (!this.pollingInterval) {
            this.startPolling();
          }
        } else {
          throw new Error('No data received from server');
        }
      } catch (error) {
        console.error('Error fetching system information:', error);

        if (this.retryCount < this.maxRetries) {
          this.retryCount++;
          setTimeout(() => this.fetchSystemInfo(), 2000);
        } else {
          this.loading = false;
          this.error = error.response?.data?.message ||
                      error.message ||
                      'Failed to connect to system service';
        }
      }
    },

    retry() {
      this.retryCount = 0;
      this.fetchSystemInfo();
    },

    startPolling() {
      this.pollingInterval = setInterval(() => {
        this.updateSystemInfo();
      }, 5000);
    },

    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
      }
    },

    async updateSystemInfo() {
      try {
        const response = await SystemService.getSystemInfo();
        if (response.data) {
          this.systemInfo = response.data;
        }
      } catch (error) {
        console.error('Error updating system information:', error);
      }
    },

    onHostnameChanged() {
      this.updateSystemInfo();
    },

    formatTempLabel(key) {
      const labels = {
        'cpu': 'CPU',
        'gpu': 'GPU',
        'tj': 'Junction',
        'thermal_zone0': 'Zone 0',
        'thermal_zone1': 'Zone 1',
        'thermal_zone2': 'Zone 2'
      };
      return labels[key] || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
  }
}
</script>

<style scoped>
.page-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
  padding-right: 40px;
  gap: 24px;
  box-sizing: border-box;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
  text-align: center;
}

.loading-container,
.error-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  padding: 40px;
  min-height: 400px;
}

.loading-container i {
  font-size: 2.5rem;
  color: var(--ark-color-blue);
}

.error-container i {
  font-size: 3rem;
  color: var(--ark-color-orange);
}

.error-container h2 {
  margin: 0;
  color: var(--ark-color-black);
}

.error-container p {
  color: var(--ark-color-black);
  opacity: 0.8;
  text-align: center;
  max-width: 400px;
}

.retry-button {
  padding: 10px 20px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.retry-button:hover {
  background-color: var(--ark-color-blue-hover);
}

.system-content {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.system-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.memory-bars {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding-top: 12px;
  border-top: 1px solid #f0f0f0;
}

.temp-scroll-container {
  max-height: 120px;
  overflow-y: auto;
  padding: 12px 0;
  border-top: 1px solid #f0f0f0;
}

.temp-item {
  display: flex;
  justify-content: space-between;
  padding: 4px 8px;
  border-radius: 4px;
}

.temp-item:hover {
  background-color: #f5f5f5;
}

.temp-label {
  font-weight: 500;
  color: #666;
  font-size: 0.9rem;
}

.temp-value {
  color: var(--ark-color-black);
  font-weight: 600;
  font-size: 0.9rem;
}

/* Responsive Design */
@media (max-width: 1200px) {
  .system-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .page-container {
    padding: 16px;
  }

  .system-grid {
    grid-template-columns: 1fr;
  }
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
