<template>
  <div class="page-container">
    <h1 class="page-title">Jetson System Information</h1>

    <div class="system-content">
      <!-- System Cards Grid -->
      <div class="system-grid">
        <!-- Hardware Card -->
        <SystemCard
          title="Hardware"
          icon="fa-microchip"
          :data="hardwareData"
          :loading="dataLoading.hardware"
        />

        <!-- Platform Card -->
        <SystemCard
          title="Platform"
          icon="fa-server"
          :data="platformData"
          :loading="dataLoading.platform"
        />

        <!-- Libraries Card -->
        <SystemCard
          title="Libraries"
          icon="fa-book"
          :data="librariesData"
          :loading="dataLoading.libraries"
        />

        <!-- Power & Temperature Card -->
        <SystemCard
          title="Power & Temperature"
          icon="fa-bolt"
          :data="powerData"
          :loading="dataLoading.power"
        >
          <template v-if="powerData" #footer>
            <div class="temperature-gauges">
              <TemperatureGauge
                v-for="(temp, key) in temperatures"
                :key="key"
                :label="key.toUpperCase()"
                :value="temp"
                :max="100"
                :warning="80"
                :critical="90"
              />
            </div>
          </template>
        </SystemCard>

        <!-- Network Card -->
        <SystemCard
          title="Network"
          icon="fa-network-wired"
          :data="networkData"
          :loading="dataLoading.network"
        />

        <!-- Storage Card -->
        <SystemCard
          title="Storage"
          icon="fa-hdd"
          :data="storageData"
          :loading="dataLoading.storage"
        >
          <template v-if="storageData" #footer>
            <DiskUsageBar
              :used="systemInfo.disk?.used || 0"
              :total="systemInfo.disk?.total || 1"
            />
          </template>
        </SystemCard>
      </div>

      <!-- Hostname Management -->
      <HostnameManager
        :currentHostname="systemInfo.interfaces?.hostname || systemInfo.network?.hostname"
        @hostnameChanged="onHostnameChanged"
      />
    </div>
  </div>
</template>

<script>
import SystemService from '@/services/SystemService';
import SystemCard from './components/SystemCard.vue';
import TemperatureGauge from './components/TemperatureGauge.vue';
import DiskUsageBar from './components/DiskUsageBar.vue';
import HostnameManager from './components/HostnameManager.vue';

export default {
  name: 'SystemPageJetson',
  components: {
    SystemCard,
    TemperatureGauge,
    DiskUsageBar,
    HostnameManager
  },
  props: {
    systemInfo: {
      type: Object,
      required: true
    },
    deviceType: {
      type: String,
      default: 'jetson'
    }
  },
  data() {
    return {
      pollingInterval: null,
      dataLoading: {
        hardware: false,
        platform: false,
        libraries: false,
        power: false,
        network: false,
        storage: false
      },
      localSystemInfo: {}
    };
  },
  computed: {
    hardwareData() {
      const hw = this.localSystemInfo.hardware;
      if (!hw) return null;

      return {
        'Model': hw.model || 'Data unavailable',
        'Module': hw.module || 'Data unavailable',
        'Serial': hw.serial_number || 'Data unavailable',
        'L4T': hw.l4t || 'Data unavailable',
        'JetPack': hw.jetpack || 'Data unavailable'
      };
    },

    platformData() {
      const platform = this.localSystemInfo.platform;
      if (!platform) return null;

      return {
        'Distribution': platform.distribution || 'Data unavailable',
        'Release': platform.release || 'Data unavailable',
        'Kernel': platform.kernel || 'Data unavailable',
        'Python': platform.python || 'Data unavailable',
        'Architecture': platform.architecture || 'Data unavailable'
      };
    },

    librariesData() {
      const libs = this.localSystemInfo.libraries;
      if (!libs) return null;

      return {
        'CUDA': libs.cuda || 'Not available',
        'OpenCV': libs.opencv || 'Not available',
        'OpenCV-CUDA': libs.opencv_cuda ? 'Enabled' : 'Disabled',
        'cuDNN': libs.cudnn || 'Not available',
        'TensorRT': libs.tensorrt || 'Not available',
        'VPI': libs.vpi || 'Not available',
        'Vulkan': libs.vulkan || 'Not available'
      };
    },

    powerData() {
      const power = this.localSystemInfo.power;
      if (!power) return null;

      return {
        'Power Mode': power.nvpmodel || 'Unknown',
        'Jetson Clocks': power.jetson_clocks ? 'Enabled' : 'Disabled',
        'Power Draw': power.total ? `${(power.total / 1000).toFixed(2)} W` : 'Unknown'
      };
    },

    temperatures() {
      const temps = this.localSystemInfo.power?.temperature;
      if (!temps) return {};

      return {
        cpu: temps.cpu || 0,
        gpu: temps.gpu || 0,
        tj: temps.tj || 0
      };
    },

    networkData() {
      const network = this.localSystemInfo.network || this.localSystemInfo.interfaces;
      if (!network) return null;

      const data = {
        'Hostname': network.hostname || 'Unknown'
      };

      const interfaces = network.interfaces || {};
      Object.entries(interfaces).forEach(([iface, ip]) => {
        data[iface] = ip;
      });

      return data;
    },

    storageData() {
      const disk = this.localSystemInfo.disk || this.localSystemInfo.resources?.disk;
      if (!disk) return null;

      return {
        'Total': disk.total ? `${disk.total.toFixed(1)} GB` : 'Unknown',
        'Used': disk.used ? `${disk.used.toFixed(1)} GB` : 'Unknown',
        'Available': disk.available ? `${disk.available.toFixed(1)} GB` : 'Unknown',
        'Usage': disk.percent ? `${disk.percent.toFixed(1)}%` : 'Unknown'
      };
    }
  },

  watch: {
    systemInfo: {
      handler(newVal) {
        this.localSystemInfo = { ...newVal };
      },
      deep: true,
      immediate: true
    }
  },

  mounted() {
    this.startPolling();
  },

  beforeUnmount() {
    this.stopPolling();
  },

  methods: {
    startPolling() {
      this.pollingInterval = setInterval(() => {
        this.fetchSystemInfo();
      }, 5000); // Poll every 5 seconds
    },

    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
        this.pollingInterval = null;
      }
    },

    async fetchSystemInfo() {
      try {
        const response = await SystemService.getSystemInfo();
        if (response.data) {
          this.localSystemInfo = response.data;
        }
      } catch (error) {
        console.error('Error updating system information:', error);
      }
    },

    onHostnameChanged(newHostname) {
      // Refresh system info after hostname change
      this.fetchSystemInfo();
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
  gap: 24px;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
  text-align: center;
}

.system-content {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.system-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 20px;
}

.temperature-gauges {
  display: flex;
  justify-content: space-around;
  padding: 12px 0;
  gap: 16px;
}

/* Responsive Design */
@media (max-width: 768px) {
  .page-container {
    padding: 16px;
  }

  .system-grid {
    grid-template-columns: 1fr;
  }

  .temperature-gauges {
    flex-direction: column;
    align-items: center;
  }
}
</style>
