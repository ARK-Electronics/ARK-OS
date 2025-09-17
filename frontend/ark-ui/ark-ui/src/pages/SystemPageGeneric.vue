<template>
  <div class="page-container">
    <h1 class="page-title">System Information</h1>

    <div class="system-content">
      <!-- Device Type Notice -->
      <div v-if="deviceType === 'unknown'" class="notice-card">
        <i class="fas fa-info-circle"></i>
        <p>Generic Linux system detected. Some features may be limited.</p>
      </div>

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

        <!-- Resources Card -->
        <SystemCard
          title="System Resources"
          icon="fa-tachometer-alt"
          :data="resourcesData"
        >
          <template v-if="memoryData" #footer>
            <div class="resource-bars">
              <ProgressBar
                label="Memory"
                :value="memoryData.percent"
                :showPercentage="true"
              />
              <ProgressBar
                label="Disk"
                :value="diskData.percent"
                :showPercentage="true"
                :warningThreshold="80"
                :criticalThreshold="90"
              />
            </div>
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
          title="Storage Details"
          icon="fa-hdd"
          :data="storageData"
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
  name: 'SystemPageGeneric',
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
      default: 'generic'
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

      const data = {};

      if (hw.type) data['Type'] = hw.type;
      if (hw.cpu_model) data['CPU Model'] = hw.cpu_model;
      if (hw.processor) data['Processor'] = hw.processor;
      if (this.localSystemInfo.resources?.cpu_count) {
        data['CPU Cores'] = this.localSystemInfo.resources.cpu_count;
      }

      return Object.keys(data).length > 0 ? data : { 'Status': 'Limited hardware information available' };
    },

    platformData() {
      const platform = this.localSystemInfo.platform;
      if (!platform) return null;

      return {
        'Distribution': platform.distribution || 'Unknown',
        'Release': platform.release || 'Unknown',
        'Kernel': platform.kernel || 'Unknown',
        'Architecture': platform.architecture || 'Unknown',
        'Python': platform.python || 'Unknown'
      };
    },

    resourcesData() {
      const resources = this.localSystemInfo.resources;
      if (!resources) return null;

      const data = {};

      if (resources.cpu_count) {
        data['CPU Cores'] = resources.cpu_count;
      }

      if (resources.memory) {
        data['Total Memory'] = `${resources.memory.total?.toFixed(2) || 0} GB`;
        data['Used Memory'] = `${resources.memory.used?.toFixed(2) || 0} GB`;
        data['Available Memory'] = `${resources.memory.available?.toFixed(2) || 0} GB`;
      }

      return data;
    },

    memoryData() {
      return this.localSystemInfo.resources?.memory || null;
    },

    diskData() {
      return this.localSystemInfo.resources?.disk || { percent: 0 };
    },

    temperatureData() {
      const temps = this.localSystemInfo.temperature;
      if (!temps || temps.message) return null;

      const data = {};

      Object.entries(temps).forEach(([key, value]) => {
        if (typeof value === 'number') {
          const label = key === 'cpu' ? 'CPU' : key.replace(/_/g, ' ');
          data[label] = `${value.toFixed(1)}°C`;
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
        'Total Storage': disk.total ? `${disk.total.toFixed(1)} GB` : 'Unknown',
        'Used Storage': disk.used ? `${disk.used.toFixed(1)} GB` : 'Unknown',
        'Available Storage': disk.available ? `${disk.available.toFixed(1)} GB` : 'Unknown',
        'Usage Percentage': disk.percent ? `${disk.percent.toFixed(1)}%` : 'Unknown'
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

.notice-card {
  background: linear-gradient(135deg, #fff3cd 0%, #ffe8a1 100%);
  border: 1px solid #ffc107;
  border-radius: 8px;
  padding: 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  color: #856404;
}

.notice-card i {
  font-size: 1.5rem;
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

.resource-bars {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding-top: 12px;
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
