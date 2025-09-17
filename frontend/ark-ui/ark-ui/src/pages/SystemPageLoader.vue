<template>
  <div class="system-page-wrapper">
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

    <component
      v-else
      :is="systemPageComponent"
      :systemInfo="systemInfo"
      :deviceType="deviceType"
    />
  </div>
</template>

<script>
import SystemService from '@/services/SystemService';
import SystemPageJetson from './SystemPageJetson.vue';
import SystemPagePi from './SystemPagePi.vue';
import SystemPageGeneric from './SystemPageGeneric.vue';

export default {
  name: 'SystemPageLoader',
  components: {
    SystemPageJetson,
    SystemPagePi,
    SystemPageGeneric
  },
  data() {
    return {
      loading: true,
      error: null,
      systemInfo: null,
      deviceType: null,
      retryCount: 0,
      maxRetries: 3
    };
  },
  computed: {
    systemPageComponent() {
      switch(this.deviceType) {
        case 'jetson':
          return 'SystemPageJetson';
        case 'pi':
          return 'SystemPagePi';
        case 'generic':
        default:
          return 'SystemPageGeneric';
      }
    }
  },
  mounted() {
    this.fetchSystemInfo();
  },
  methods: {
    async fetchSystemInfo() {
      this.loading = true;
      this.error = null;

      try {
        const response = await SystemService.getSystemInfo();

        if (response.data) {
          this.systemInfo = response.data;
          this.deviceType = response.data.device_type || 'unknown';
          this.loading = false;
          this.retryCount = 0;
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
    }
  }
}
</script>

<style scoped>
.system-page-wrapper {
  width: 100%;
  min-height: 400px;
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

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
