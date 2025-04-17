<template>
  <div class="log-viewer-backdrop">
    <div class="log-viewer-container">
      <h2>{{ serviceName }}</h2>
      <pre class="log-content" ref="logContent">
        {{ logs }}
      </pre>
      <div class="actions">
        <button @click="closeViewer" class="close-button">Close</button>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  props: ['serviceName'],
  data() {
    return {
      logs: '',
      logPollingInterval: null
    };
  },
  mounted() {
    this.startPolling();
  },
  beforeUnmount() {
    this.stopPolling();
  },
  methods: {
    fetchLogs() {
      axios.get(`/api/service/logs?serviceName=${this.serviceName}`)
        .then(response => {
          if (response.data.status === 'success') {
            this.logs = response.data.logs;
          } else {
            console.error('Error fetching logs:', response.data.message);
          }
        })
        .catch(error => {
          console.error('Error fetching logs:', error);
        });
    },
    startPolling() {
      this.fetchLogs(); // Initial fetch
      this.logPollingInterval = setInterval(() => {
        this.fetchLogs();
      }, 1000); // Poll every second
    },
    stopPolling() {
      if (this.logPollingInterval) {
        clearInterval(this.logPollingInterval);
      }
    },
    closeViewer() {
      this.stopPolling();
      this.$emit('close-viewer');
    },
    scrollToBottom() {
      const logContent = this.$refs.logContent;
      logContent.scrollTop = logContent.scrollHeight;
    }
  },
  watch: {
    logs() {
      this.$nextTick(() => {
        this.scrollToBottom();
      });
    }
  }
}
</script>

<style scoped>
.log-viewer-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: var(--ark-color-black);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.log-viewer-container {
  background-color: var(--ark-color-white);
  padding: 30px;
  border-radius: 12px;
  width: 600px;
  max-width: 90%;
  max-height: 80vh;
  box-shadow: 0px 0px 20px var(--ark-color-black-shadow);
  overflow-y: auto;
}

h2 {
  text-align: center;
  margin-bottom: 20px;
  color: var(--ark-color-black);
}

.log-content {
  background-color: var(--ark-color-black-shadow);
  padding: 20px;
  border-radius: 4px;
  border: 1px solid var(--ark-color-black-shadow);
  max-height: 60vh;
  overflow-y: auto;
  white-space: pre-wrap; /* Ensures that the text maintains line breaks */
  font-family: monospace; /* Uses a monospaced font for log output */
  color: var(--ark-color-black-bold);
}

.actions {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.close-button {
  padding: 12px 20px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 600;
  background-color: var(--ark-color-red);
  color: var(--ark-color-white);;
  transition: background-color 0.3s ease;
}

.close-button:hover {
  background-color: var(--ark-color-red-hover);
}
</style>
