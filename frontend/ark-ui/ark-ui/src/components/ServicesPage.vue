<template>
  <div class="services-container">
    <h2>Services</h2>
    <div class="services-grid">
      <div v-for="service in services.filter(service => service.visible === 'true')"
           :key="service.name"
           class="service-box"
           :class="{
            'active-glow': service.active === 'active',
            'inactive-glow': service.active === 'inactive',
            'deactivating-glow': service.active === 'deactivating'}">

        <p class="service-name"><strong>{{ service.name }}</strong></p>
        <div class="service-actions">
          <template v-if="service.active === 'deactivating'">
            <i class="fas fa-spinner fa-spin"></i> <!-- This will show a spinning wheel -->
          </template>
          <template v-else>
            <button v-if="service.active === 'active'" @click="stopService(service.name)" title="Stop service">
              <i class="fas fa-stop"></i>
            </button>
            <button v-if="service.active === 'inactive'" @click="startService(service.name)" title="Start service">
              <i class="fas fa-play"></i>
            </button>
            <button @click="openLogViewer(service.name)" title="View journal logs">
              <i class="fas fa-book"></i>
            </button>
            <button v-if="service.config_file !== ''" @click="openConfigEditor(service.name)" title="Edit config file">
              <i class="fas fa-pencil-alt"></i>
            </button>
            <div v-else class="placeholder"></div>
          </template>
        </div>
        <div class="status-row">
          <label class="switch">
            <input type="checkbox" :checked="service.enabled === 'enabled'" @change="toggleService(service)">
            <span class="slider round"></span>
          </label>
          <p class="status-label">{{ 'Autostart' }}</p>
        </div>
      </div>
    </div>

    <TomlEditor
      v-if="showTomlEditor"
      :serviceName="selectedService"
      @close-editor="closeConfigEditor"
    />

    <MavlinkRouterEditor
      v-if="showMavlinkRouterEditor"
      :serviceName="selectedService"
      @close-editor="closeConfigEditor"
    />

    <!-- Log Viewer Modal -->
    <LogViewer
      v-if="showLogViewer"
      :serviceName="selectedService"
      @close-viewer="closeLogViewer"
    />
  </div>
</template>

<script>
import axios from 'axios';
import TomlEditor from './TomlEditor.vue';
import MavlinkRouterEditor from './MavlinkRouterEditor.vue';
import LogViewer from './LogViewer.vue';

export default {
  components: {
    TomlEditor,
    MavlinkRouterEditor,
    LogViewer
  },
  data() {
    return {
      services: [],
      selectedService: null,
      showTomlEditor: false,
      showMavlinkRouterEditor: false,
      showLogViewer: false,
      pollingInterval: null,
    };
  },
  mounted() {
    this.fetchServiceStatuses();
    this.startPolling();
  },
  beforeUnmount() {
    this.stopPolling();
  },
  methods: {
    startPolling() {
      this.pollingInterval = setInterval(() => {
        this.fetchServiceStatuses();
      }, 1000); // Poll every second
    },
    stopPolling() {
      if (this.pollingInterval) {
        clearInterval(this.pollingInterval);
      }
    },
    fetchServiceStatuses() {
      axios.get('/api/service/statuses')
        .then(response => {
          this.services = response.data.services;
        })
        .catch(error => {
          console.error('Error fetching service statuses:', error);
        });
    },
    toggleService(service) {
      const newStatus = service.enabled === 'enabled' ? 'disable' : 'enable';
      axios.post(`/api/service/${newStatus}?serviceName=${service.name}`)
        .then(response => {
          if (response.status === 200) {
            console.log(`Service ${service.name} ${newStatus}d successfully`);
            service.enabled = newStatus === 'enable' ? 'enabled' : 'disabled';
          } else {
            console.error(`Failed to ${newStatus} service ${service.name}`);
            alert(`Failed to ${newStatus} service ${service.name}`);
          }
        })
        .catch(error => {
          console.error(`Error ${newStatus} service:`, error);
          alert(`Error ${newStatus} service`);
          // Revert the toggle if there was an error
          service.enabled = service.enabled === 'enabled' ? 'disabled' : 'enabled';
        });
    },
    startService(serviceName) {
      axios.post(`/api/service/start?serviceName=${serviceName}`)
        .then(response => {
          if (response.status === 200) {
            console.log(`Service ${serviceName} started successfully`);
            this.fetchServiceStatuses();
          } else {
            console.error(`Failed to start service ${serviceName}`);
          }
        })
        .catch(error => {
          console.error('Error starting service:', error);
        });
    },
    stopService(serviceName) {
      axios.post(`/api/service/stop?serviceName=${serviceName}`)
        .then(response => {
          if (response.status === 200) {
            console.log(`Service ${serviceName} stopped successfully`);
            this.fetchServiceStatuses();
          } else {
            console.error(`Failed to stop service ${serviceName}`);
          }
        })
        .catch(error => {
          console.error('Error stopping service:', error);
        });
    },
    openConfigEditor(serviceName) {
      this.stopPolling();
      this.selectedService = serviceName;
      if (serviceName === "mavlink-router") {
        this.showMavlinkRouterEditor = true;
      } else {
        this.showTomlEditor = true;
      }
    },
    closeConfigEditor() {
      this.startPolling();
      this.showTomlEditor = false;
      this.showMavlinkRouterEditor = false;
      this.selectedService = null;
    },
    openLogViewer(serviceName) {
      console.log(`Opening log viewer for ${serviceName}`);
      this.selectedService = serviceName;
      this.showLogViewer = true;
    },
    closeLogViewer() {
      this.showLogViewer = false;
      this.selectedService = null;
    }
  }
}
</script>

<style scoped>
h1, h2 {
  text-align: center;
  color: var(--ark-color-black);
}

.services-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 20px;
}

.label, p {
  font-size: 16px;
  color: var(--ark-color-black);
  margin: 0;
}

.status-label {
  font-size: 15px;
  color: var(--ark-color-black);
}

.services-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(120px, 1fr));
  gap: 10px;
  width: 100%;
}

.service-box {
  border: 2px solid var(--ark-color-black-shadow);
  padding: 10px;
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
  transition: box-shadow 0.3s ease-in-out;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.service-name {
  font-size: 18px;
  color: var(--ark-color-black);
  text-align: center;
}

.status-row {
  display: flex;
  align-items: center;
  margin: 2px;
}

.status-indicator {
  height: 10px;
  width: 10px;
  border-radius: 50%;
  margin-right: 15px;
}

.background-green {
  background-color: var(--ark-color-green);
}

.background-red {
  background-color: var(--ark-color-red);
}

.active-glow {
  box-shadow: 0px 0px 8px var(--ark-color-green);
}

.inactive-glow {
  box-shadow: 0px 0px 8px var(--ark-color-red);
}

.deactivating-glow {
  box-shadow: 0px 0px 8px var(--ark-color-orange);
}

.service-actions {
  display: flex;
  justify-content: space-around;
  margin-top: 10px;
}

.service-actions button {
  font-size: 15px;
  border: none;
  margin: 5px;
  border-radius: 4px;
  background-color: var(--ark-color-white);
  color: var(--ark-color-black);
  cursor: pointer;
  transition: transform 0.3s ease;
}

.service-actions button:hover {
  transform: scale(1.3);
}

.placeholder {
  width: 30px; /* Adjust this width to match the size of your buttons */
  height: 30px; /* Adjust this height to match the size of your buttons */
}

/* Slider */
.switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 20px;
  margin-right: 10px;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: var(--ark-color-red);
  transition: 0.4s;
  border-radius: 20px;
}

.slider:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  border-radius: 50%;
  left: 2px;
  bottom: 2px;
  background-color: white;
  transition: 0.4s;
}

input:checked + .slider {
  background-color: var(--ark-color-green);
}

input:checked + .slider:before {
  transform: translateX(20px);
}

.fa-spinner {
  font-size: 1.5em; /* Adjust size if necessary */
  color: var(--ark-color-black);
}

.fa-spinner.fa-spin {
  animation: spin 1s infinite linear;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

</style>
