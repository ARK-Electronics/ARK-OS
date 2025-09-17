<template>
  <div class="editor-backdrop">
    <div class="editor-container">
      <div class="editor-content">
        <h1>Mavlink Router Endpoints</h1>

        <div class="endpoint-list">
          <div v-for="(endpoint, index) in endpoints" :key="index" :class="['endpoint-row', endpoint.isEditing ? 'editing' : '']">
            <div class="endpoint-header">
              <!-- Endpoint Name (Editable if Unlocked) -->
              <div class="name-input-wrapper">
                <input
                  v-if="endpoint.isEditing"
                  v-model="endpoint.name"
                  class="editable-input"
                  :class="{ 'error': !endpoint.name }"
                  placeholder="Enter endpoint name"
                />
                <p v-else><strong>{{ endpoint.name }}</strong></p>

                <!-- Required Tag if Name is Empty -->
                <p v-if="!endpoint.name && endpoint.isEditing" class="required-tag">Required</p>
              </div>

              <!-- Endpoint Type (Editable if Unlocked) -->
              <select v-if="endpoint.isEditing" v-model="endpoint.type" @change="handleTypeChange(index)" class="editable-select">
                <option value="Udp">UDP</option>
                <option value="Uart">UART</option>
                <option value="Tcp">TCP</option>
              </select>
              <p v-else class="uppercase">{{ endpoint.type }}</p>

              <!-- Delete Button (Only visible when unlocked) -->
              <button v-if="endpoint.isEditing" class="remove-button" @click="removeEndpoint(index)">
                <i class="fas fa-trash"></i>
              </button>

              <!-- Lock/Unlock Button -->
              <button class="lock-button" @click="toggleEdit(index)">
                <i :class="endpoint.isEditing ? 'fas fa-lock-open' : 'fas fa-lock'"></i>
              </button>
            </div>

            <!-- Display endpoint options based on type -->
            <div class="endpoint-details">
              <!-- Udp Endpoint Options -->
              <div v-if="endpoint.type === 'Udp'">
                <label>Mode</label>
                <select v-model="endpoint.config.Mode" :disabled="!endpoint.isEditing">
                  <option value="Normal">Normal</option>
                  <option value="Server">Server</option>
                </select>

                <label>Address</label>
                <input type="text" v-model="endpoint.config.Address" :disabled="!endpoint.isEditing" />

                <label>Port</label>
                <input type="number" v-model="endpoint.config.Port" :disabled="!endpoint.isEditing" />
              </div>

              <!-- Uart Endpoint Options -->
              <div v-if="endpoint.type === 'Uart'">
                <label>Device</label>
                <input type="text" v-model="endpoint.config.Device" :disabled="!endpoint.isEditing" />

                <label>Baud</label>
                <input type="text" v-model="endpoint.config.Baud" :disabled="!endpoint.isEditing" />

                <label>FlowControl</label>
                <select v-model="endpoint.config.FlowControl" :disabled="!endpoint.isEditing">
                  <option value="true">True</option>
                  <option value="false">False</option>
                </select>
              </div>

              <!-- Tcp Endpoint Options -->
              <div v-if="endpoint.type === 'Tcp'">
                <label>Address</label>
                <input type="text" v-model="endpoint.config.Address" :disabled="!endpoint.isEditing" />

                <label>Port</label>
                <input type="number" v-model="endpoint.config.Port" :disabled="!endpoint.isEditing" />

                <label>Retry Timeout</label>
                <input type="number" v-model="endpoint.config.RetryTimeout" :disabled="!endpoint.isEditing" />
              </div>
            </div>
          </div>
        </div>

        <button class="add-button" @click="addEndpoint">Add Endpoint</button>
      </div>

      <div class="actions-container">
        <div class="actions">
          <button @click="saveConfig" class="save-button">Save Configuration</button>
          <button @click="cancelConfig" class="cancel-button">Cancel</button>
        </div>
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
      originalConfigLines: null,
      endpoints: [],
    };
  },
  mounted() {
    this.loadConfig();
  },
  methods: {
    loadConfig() {
      axios.get(`/api/service/config?serviceName=${this.serviceName}`)
        .then(response => {
          const configData = response.data.data;
          // Store the original file lines
          this.originalConfigLines = configData.split('\n');
          this.endpoints = this.parseEndpoints(configData);
        })
        .catch(error => {
          console.error('Error fetching config:', error);
        });
    },
    parseEndpoints(configData) {
      const parsedEndpoints = [];
      const lines = configData.split('\n');
      let currentEndpoint = null;

      lines.forEach(line => {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || !trimmed) return; // Ignore comments and empty lines

        if (trimmed.startsWith('[')) {
          const match = trimmed.match(/\[(.*?) (.*?)\]/);
          if (match) {
            const type = match[1]; // Endpoint type
            const name = match[2]; // Endpoint name

            if (type === 'UdpEndpoint' || type === 'UartEndpoint' || type === 'TcpEndpoint') {
              if (currentEndpoint) parsedEndpoints.push(currentEndpoint); // Push previous endpoint

              currentEndpoint = {
                type: type.replace('Endpoint', ''), // Udp, Uart, Tcp
                name,
                config: this.getDefaultConfig(type),
                isEditing: false
              };
            } else {
              currentEndpoint = null; // Ignore non-endpoint sections
            }
          }
        } else if (currentEndpoint) {
          const [key, value] = trimmed.split('=').map(str => str.trim());
          currentEndpoint.config[key] = value;
        }
      });

      if (currentEndpoint) parsedEndpoints.push(currentEndpoint); // Push the last endpoint
      return parsedEndpoints;
    },
    saveConfig() {
      // Check for any endpoints with empty names before saving
      const hasInvalidEndpoints = this.endpoints.some(endpoint => !endpoint.name);

      if (hasInvalidEndpoints) {
        alert('Please provide names for all endpoints.');
        return;
      }

      // Check for duplicate endpoint names
      const endpointNames = this.endpoints.map(endpoint => endpoint.name);
      const duplicateNames = endpointNames.filter((name, index, self) => self.indexOf(name) !== index);

      if (duplicateNames.length > 0) {
        alert('Duplicate endpoint names found. Please ensure all endpoint names are unique.');
        return;
      }

      const updatedConfigLines = this.generateUpdatedConfigLines();
      axios.post(`/api/service/config?serviceName=${this.serviceName}`, { config: updatedConfigLines.join('\n') })
        .then(response => {
          if (response.data.status === 'success') {
            this.$emit('close-editor');
          } else {
            alert('Error saving configuration');
          }
        })
        .catch(error => {
          console.error('Error saving config:', error);
        });
    },
    generateUpdatedConfigLines() {
      const updatedConfigLines = [];
      const endpointsToKeep = new Set(this.endpoints.map(ep => ep.name)); // Endpoint names to keep
      let insideEndpointSection = false;
      let currentEndpoint = null;
      let skipSection = false;
      let sectionLines = [];

      this.originalConfigLines.forEach((line) => {
        const trimmed = line.trim();

        // Check if this is the start of a new section
        if (trimmed.startsWith('[')) {
          // Before processing a new section, add the previous one if it's not deleted
          if (!skipSection && insideEndpointSection && currentEndpoint) {
            updatedConfigLines.push(...sectionLines);
          }

          const match = trimmed.match(/\[(.*?) (.*?)\]/);
          if (match) {
            const type = match[1];
            const name = match[2];

            // Determine if this section is an endpoint
            if (type === 'UdpEndpoint' || type === 'UartEndpoint' || type === 'TcpEndpoint') {
              insideEndpointSection = true;
              currentEndpoint = this.endpoints.find(ep => ep.name === name);

              // If the endpoint is to be kept, prepare to update/keep its section
              if (endpointsToKeep.has(name)) {
                sectionLines = []; // Buffer to hold lines for this section
                sectionLines.push(line); // Add the section header
                skipSection = false; // We're keeping this section
              } else {
                skipSection = true; // We're skipping this section (deleted endpoint)
              }
            } else {
              // Non-endpoint sections, just add them directly
              insideEndpointSection = false;
              currentEndpoint = null;
              updatedConfigLines.push(line);
              skipSection = false;
            }
          } else {
            insideEndpointSection = false;
            currentEndpoint = null;
            updatedConfigLines.push(line); // If no match, continue adding lines
          }
        } else if (insideEndpointSection && !skipSection) {
          // If inside an endpoint section that we're keeping, update the lines
          const [key] = trimmed.split('=').map(str => str.trim());
          if (key in currentEndpoint.config) {
            sectionLines.push(`${key} = ${currentEndpoint.config[key]}`);
          } else {
            sectionLines.push(line); // Preserve other lines (e.g., comments)
          }
        } else if (!insideEndpointSection && !skipSection) {
          // Outside of any endpoint section, keep the line as is
          updatedConfigLines.push(line);
        }
      });

      // If we ended inside a section, add it
      if (!skipSection && insideEndpointSection && currentEndpoint) {
        updatedConfigLines.push(...sectionLines);
      }

      // Append any new endpoints that weren't part of the original config
      this.endpoints.forEach(endpoint => {
        const sectionHeader = `[${endpoint.type}Endpoint ${endpoint.name}]`;
        if (!this.originalConfigLines.some(line => line.includes(sectionHeader))) {
          // New endpoint, append to the end of the config
          updatedConfigLines.push(sectionHeader);
          for (const key in endpoint.config) {
            updatedConfigLines.push(`${key} = ${endpoint.config[key]}`);
          }
          updatedConfigLines.push(''); // Add a blank line after the section
        }
      });

      return updatedConfigLines;
    },
    getDefaultConfig(type) {
      // Provide default config based on the endpoint type
      switch (type) {
        case 'Udp':
          return { Mode: 'Normal', Address: '0.0.0.0', Port: 14550 };
        case 'Uart':
          return { Device: '/dev/serial0', Baud: '115200', FlowControl: 'false' };
        case 'Tcp':
          return { Address: '127.0.0.1', Port: 5760, RetryTimeout: 5 };
        default:
          return {};
      }
    },
    addEndpoint() {
      this.endpoints.push({
        type: 'Udp', // Default type
        name: '',
        config: this.getDefaultConfig('Udp'),
        isEditing: true
      });
    },
    handleTypeChange(index) {
      // Reset the config when type changes
      const endpoint = this.endpoints[index];
      endpoint.config = this.getDefaultConfig(endpoint.type);
    },
    toggleEdit(index) {
      this.endpoints[index].isEditing = !this.endpoints[index].isEditing;
    },
    removeEndpoint(index) {
      this.endpoints.splice(index, 1);
      this.generateUpdatedConfigLines();
    },
    cancelConfig() {
      this.$emit('close-editor');
    },
  }
};

</script>

<style scoped>
.editor-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.7);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.editor-container {
  background-color: var(--ark-color-white);
  border-radius: 12px;
  width: 700px;
  max-width: 90%;
  box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.4);
  display: flex;
  flex-direction: column;
  max-height: 90vh;
}

.editor-content {
  padding: 30px;
  overflow-y: auto;
}

h1 {
  text-align: center;
  color: var(--ark-color-black);
  margin-bottom: 25px;
}

.endpoint-row {
  display: flex;
  flex-direction: column;
  margin-bottom: 20px; /* Increased margin for more spacing */
  padding: 15px; /* Added padding inside each block */
  border: 1px solid var(--ark-color-black-shadow); /* Added border for clearer separation */
  border-radius: 8px; /* Rounded corners for a cleaner look */
  background-color: var(--ark-color-white); /* Background color to make each block distinct */
  box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1); /* Subtle shadow for depth */
}

.endpoint-row.editing {
/*  border-color: var(--ark-color-green-shadow);*/
  border: 2px solid var(--ark-color-green);
}

.endpoint-header {
  display: grid;
  grid-template-columns: 1fr 1fr auto auto;
  align-items: center;
  gap: 10px;
}

.name-input-wrapper {
  position: relative;
}

.editable-input.error {
  border: 2px solid red;
}

.required-tag {
  color: red;
  font-size: 12px;
  margin-top: 2px;
}

.editable-input,
.editable-select {
  font-size: 16px;
  border: 1px solid var(--ark-color-black-shadow);
  padding: 14.5px;
  border-radius: 4px;
}

.lock-button, .remove-button {
  background-color: transparent;
  border: none;
  cursor: pointer;
  font-size: 18px;
  color: var(--ark-color-black);
}

.lock-button:hover {
  color: var(--ark-color-green);
}

.remove-button:hover {
  color: var(--ark-color-red);
}

input, select {
  padding: 8px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
  font-size: 14px;
  width: 100%; /* Adjust the width */
  max-width: 100%; /* Set a maximum width to limit the size */
  box-sizing: border-box; /* Ensure padding is included in the total width */
}

.endpoint-details {
  font-size: 14px;
  color: var(--ark-color-black);
  display: flex;
  flex-direction: column;
  gap: 5px;
}

label {
  font-weight: bold;
  margin-right: 10px;
}

input, select {
  padding: 8px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
  font-size: 14px;
  width: 100%;
}

.add-button {
  margin-top: 20px;
  padding: 12px;
  border: none;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border-radius: 6px;
  cursor: pointer;
  font-size: 16px;
  margin-bottom: 20px;
}

.add-button:hover {
  background-color: var(--ark-color-blue-hover);
}

.actions-container {
  background-color: var(--ark-color-white);
  border-top: 1px solid var(--ark-color-black-shadow);
  border-radius: 0 0 12px 12px;
  padding: 20px 30px;
  position: sticky;
  bottom: 0;
}

.actions {
  display: flex;
  justify-content: space-between;
  width: 100%;
}

.save-button,
.cancel-button {
  padding: 12px 20px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 600;
  color: var(--ark-color-white);
}

.save-button {
  background-color: var(--ark-color-green);
}

.save-button:hover {
  background-color: var(--ark-color-green-hover);
}

.cancel-button {
  background-color: var(--ark-color-red);
}

.cancel-button:hover {
  background-color: var(--ark-color-red-hover);
}

.uppercase {
  text-transform: uppercase;
}
</style>
