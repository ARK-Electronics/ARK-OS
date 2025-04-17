<template>
  <div>
    <div v-if="loading" class="loading-container">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Loading system information...</p>
    </div>
    <component v-else :is="systemPageComponent" :initialSystemInfo="systemInfo"></component>
  </div>
</template>

<script>
import SystemService from '@/services/SystemService';
import SystemPageJetson from './SystemPageJetson.vue';
import SystemPagePi from './SystemPagePi.vue';

export default {
  name: 'SystemPageLoader',
  components: {
    SystemPageJetson,
    SystemPagePi,
  },
  data() {
    return {
      loading: true,
      systemInfo: null,
      deviceType: null
    };
  },
  computed: {
    systemPageComponent() {
      if (this.deviceType === 'jetson') {
        return 'SystemPageJetson';
      } else if (this.deviceType === 'pi') {
        return 'SystemPagePi';
      } else {
        console.log("falling back!!!")
        return 'SystemPageJetson';
      }
    }
  },
  mounted() {
    this.fetchSystemInfo();
  },
  methods: {
    async fetchSystemInfo() {
      try {
        const response = await SystemService.getSystemInfo();
        if (response.data) {
          this.systemInfo = response.data;
          // Get device type from the response
          this.deviceType = response.data.hardware?.type || 'unknown';
          this.loading = false;
        }
      } catch (error) {
        console.error('Error fetching system information:', error);
        this.loading = false;
        this.deviceType = 'unknown';
      }
    }
  }
}
</script>

<style scoped>
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
</style>
