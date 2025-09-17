<template>
  <div class="page-container">
    <h1 class="page-title">Raspberry Pi System Information</h1>

    <div class="system-content">
      <!-- System Cards Grid -->
      <div class="system-grid">
        <!-- Hardware Card -->
        <SystemCard
          title="Hardware"
          icon="fa-raspberry-pi"
          :data="hardwareData"
        />

        <!-- Platform Card -->
        <SystemCard
          title="Platform"
          icon="fa-server"
          :data="platformData"
        />

        <!-- Resources Card -->
        <SystemCard
          title="System Resources"
          icon="fa-microchip"
          :data="resourcesData"
        >
          <template v-if="memoryPercent" #footer>
            <ProgressBar
              label="Memory Usage"
              :value="memoryPercent"
              :showPercentage="true"
            />
          </template>
        </SystemCard>

        <!-- Temperature Card -->
        <SystemCard
          v-if="temperatureData"
          title="Temperature"
          icon="fa-temperature-high"
          :data="temperatureData"
        />

        <!-- Network Card -->
        <SystemCard
          title="Network"
          icon="fa-network-wired"
          :data="networkData"
        />

        <!-- Storage Card -->
        <SystemCard
          title="Storage"
          icon="fa-hdd"
          :data="storageData"
        >
          <template v-if="diskPercent" #footer>
            <ProgressBar
              label="Disk Usage"
              :value="diskPercent"
              :showPercentage="true"
              :warningThreshold="80"
              :criticalThreshold="90"
            />
          </template>
        </SystemCard>

        <!-- Throttling Status Card (Pi specific) -->
        <SystemCard
          v-if="throttlingData"
          title="Throttling Status"
          icon="fa-exclamation-triangle"
          :data="throttlingData"
        />
      </div>

      <!-- Hostname Management -->
      <HostnameManager
        :currentHostname="systemInfo.network?.hostname"
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
  name: 'SystemPagePi',
  components: {
    SystemCard,
    ProgressBar,
    HostnameManager
  },
  props: {
    systemInfo: {
      type: Object,
      required: true
    },
    deviceType: {
      type: String,
      default: 'pi'
    }
  },
  data() {
    return {
      pollingInterval: null,
      localSystemInfo: {}
    };
  },
  computed: {
    hardwareData() {
      const hw = this.localSystemInfo.hardware;
      if (!hw) return null;

      return {
        'Model': hw.model || 'Unknown Raspberry Pi',
        'Serial Number': hw.serial_number || 'Unknown',
        'Hardware': hw.hardware || 'Unknown',
        'Revision': hw.revision || 'Unknown',
        'GPU Memory': hw.gpu_memory || 'Unknown'
      };
    },

    platformData() {
      const platform = this.localSystemInfo.platform;
      if (!platform) return null;

      return {
        'Distribution': platform.distribution || 'Unknown',
        'Release': platform.release || 'Unknown',
        'Kernel': platform.kernel || 'Unknown',
        'Python': platform.python || 'Unknown',
        'Architecture': platform.architecture || 'Unknown'
      };
    },

    resourcesData() {
      const resources = this.localSystemInfo.resources;
      if (!resources) return null;

      const data = {
        'CPU Cores': resources.cpu_count || 'Unknown'
      };

      if (resources.memory) {
        data['Total Memory'] = `${resources.memory.total?.toFixed(2) || 0} GB`;
        data['Available Memory'] = `${resources.memory.available?.toFixed(2) || 0} GB`;
      }

      return data;
    },

    memoryPercent() {
      return this.localSystemInfo.resources?.memory?.percent || 0;
    },

    temperatureData() {
      const temps = this.localSystemInfo.temperature;
      if (!temps || temps.message) return null;

      const data = {};
      if (temps.cpu !== undefined) {
        data['CPU Temperature'] = `${temps.cpu.toFixed(1)}°C`;
      }

      // Add any other temperature zones
      Object.entries(temps).forEach(([zone, temp]) => {
        if (zone !== 'cpu' && typeof temp === 'number') {
          data[zone] = `${temp.toFixed(1)}°C`;
        }
      });

      return Object.keys(data).length > 0 ? data : null;
    },

    networkData() {
      const network = this.localSystemInfo.network;
      if (!network) return null;

      const data = {
        'Hostname': network.hostname || 'Unknown'
      };

      if (network.interfaces) {
        Object.entries(network.interfaces).forEach(([iface, ip]) => {
          data[iface] = ip;
        });
      }

      return data;
    },

    storageData() {
      const disk = this.localSystemInfo.resources?.disk;
      if (!disk) return null;

      return {
        'Total': disk.total ? `${disk.total.toFixed(1)} GB` : 'Unknown',
        'Used': disk.used ? `${disk.used.toFixed(1)} GB` : 'Unknown',
        'Available': disk.available ? `${disk.available.toFixed(1)} GB` : 'Unknown'
      };
    },

    diskPercent() {
      return this.localSystemInfo.resources?.disk?.percent || 0;
    },

    throttlingData() {
      const status = this.localSystemInfo.hardware?.throttling_status;
      if (!status) return null;

      return {
        'Under Voltage': status.under_voltage ? '⚠️ Yes' : '✓ No',
        'Frequency Capped': status.frequency_capped ? '⚠️ Yes' : '✓ No',
        'Currently Throttled': status.throttled ? '⚠️ Yes' : '✓ No',
        'Soft Temp Limit': status.soft_temp_limit ? '⚠️ Yes' : '✓ No'
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
      }, 5000);
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

    onHostnameChanged() {
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

@media (max-width: 768px) {
  .page-container {
    padding: 16px;
  }

  .system-grid {
    grid-template-columns: 1fr;
  }
}
</style>
