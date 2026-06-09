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

              <!-- Message Filtering Section (all endpoint types) -->
              <div class="msg-filter-section">
                <button
                  type="button"
                  class="msg-filter-toggle"
                  @click="toggleMsgFilter(index)"
                >
                  <i :class="endpoint.msgFilterOpen ? 'fas fa-chevron-down' : 'fas fa-chevron-right'"></i>
                  Message Filtering
                  <span v-if="endpoint.msgFilterOut.mode !== 'none'" :class="['msg-filter-badge', endpoint.msgFilterOut.mode]">
                    Out: {{ endpoint.msgFilterOut.mode === 'allow' ? 'Allow' : 'Block' }}
                    ({{ endpoint.msgFilterOut.ids.length }})
                  </span>
                  <span v-if="endpoint.msgFilterIn.mode !== 'none'" :class="['msg-filter-badge', endpoint.msgFilterIn.mode]">
                    In: {{ endpoint.msgFilterIn.mode === 'allow' ? 'Allow' : 'Block' }}
                    ({{ endpoint.msgFilterIn.ids.length }})
                  </span>
                </button>

                <div v-if="endpoint.msgFilterOpen" class="msg-filter-body">

                  <!-- Outbound filter -->
                  <div class="msg-filter-direction-block">
                    <div class="msg-filter-direction-label">
                      <span class="direction-pill out">OUT</span>
                      <span class="direction-desc">Controls which messages are sent <em>out</em> of this endpoint</span>
                    </div>
                    <div class="msg-filter-mode">
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterOut.mode" value="none" :disabled="!endpoint.isEditing" />
                        None
                      </label>
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterOut.mode" value="allow" :disabled="!endpoint.isEditing" />
                        AllowMsgIdOut
                      </label>
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterOut.mode" value="block" :disabled="!endpoint.isEditing" />
                        BlockMsgIdOut
                      </label>
                    </div>
                    <div v-if="endpoint.msgFilterOut.mode !== 'none'" class="msg-id-area">
                      <div class="msg-id-tags">
                        <span
                          v-for="(id, i) in endpoint.msgFilterOut.ids"
                          :key="i"
                          :class="['msg-id-tag', endpoint.msgFilterOut.mode]"
                        >
                          {{ id }}
                          <button
                            v-if="endpoint.isEditing"
                            type="button"
                            class="tag-remove"
                            @click="removeMsgId(index, 'out', i)"
                            title="Remove ID"
                          >&times;</button>
                        </span>
                        <span v-if="endpoint.msgFilterOut.ids.length === 0 && !endpoint.isEditing" class="msg-id-empty">No IDs configured</span>
                      </div>
                      <div v-if="endpoint.isEditing" class="msg-id-input-row">
                        <input
                          type="number"
                          min="0"
                          v-model="endpoint.msgFilterOut.newId"
                          @keydown.enter.prevent="addMsgId(index, 'out')"
                          placeholder="Enter message ID"
                          class="msg-id-input"
                        />
                        <button type="button" class="msg-id-add-btn" @click="addMsgId(index, 'out')">
                          <i class="fas fa-plus"></i> Add
                        </button>
                      </div>
                      <p v-if="endpoint.msgFilterOut.idError" class="msg-id-error">{{ endpoint.msgFilterOut.idError }}</p>
                    </div>
                  </div>

                  <!-- Inbound filter -->
                  <div class="msg-filter-direction-block">
                    <div class="msg-filter-direction-label">
                      <span class="direction-pill in">IN</span>
                      <span class="direction-desc">Controls which messages are accepted <em>in</em> to this endpoint</span>
                    </div>
                    <div class="msg-filter-mode">
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterIn.mode" value="none" :disabled="!endpoint.isEditing" />
                        None
                      </label>
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterIn.mode" value="allow" :disabled="!endpoint.isEditing" />
                        AllowMsgIdIn
                      </label>
                      <label class="radio-label">
                        <input type="radio" v-model="endpoint.msgFilterIn.mode" value="block" :disabled="!endpoint.isEditing" />
                        BlockMsgIdIn
                      </label>
                    </div>
                    <div v-if="endpoint.msgFilterIn.mode !== 'none'" class="msg-id-area">
                      <div class="msg-id-tags">
                        <span
                          v-for="(id, i) in endpoint.msgFilterIn.ids"
                          :key="i"
                          :class="['msg-id-tag', endpoint.msgFilterIn.mode]"
                        >
                          {{ id }}
                          <button
                            v-if="endpoint.isEditing"
                            type="button"
                            class="tag-remove"
                            @click="removeMsgId(index, 'in', i)"
                            title="Remove ID"
                          >&times;</button>
                        </span>
                        <span v-if="endpoint.msgFilterIn.ids.length === 0 && !endpoint.isEditing" class="msg-id-empty">No IDs configured</span>
                      </div>
                      <div v-if="endpoint.isEditing" class="msg-id-input-row">
                        <input
                          type="number"
                          min="0"
                          v-model="endpoint.msgFilterIn.newId"
                          @keydown.enter.prevent="addMsgId(index, 'in')"
                          placeholder="Enter message ID"
                          class="msg-id-input"
                        />
                        <button type="button" class="msg-id-add-btn" @click="addMsgId(index, 'in')">
                          <i class="fas fa-plus"></i> Add
                        </button>
                      </div>
                      <p v-if="endpoint.msgFilterIn.idError" class="msg-id-error">{{ endpoint.msgFilterIn.idError }}</p>
                    </div>
                  </div>

                </div>
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
function emptyFilter() {
  return { mode: 'none', ids: [], newId: '', idError: '' };
}
// Strip inline comments and trim whitespace from a config value
function stripComment(value) {
  const idx = value.indexOf('#');
  return idx === -1 ? value.trim() : value.slice(0, idx).trim();
}

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

            // Determine if this section is an endpoint
            if (type === 'UdpEndpoint' || type === 'UartEndpoint' || type === 'TcpEndpoint') {
              if (currentEndpoint) parsedEndpoints.push(currentEndpoint); // Push previous endpoint

              currentEndpoint = {
                type: type.replace('Endpoint', ''), // Udp, Uart, Tcp
                name,
                config: this.getDefaultConfig(type),
                isEditing: false,
                msgFilterOpen: false,
                msgFilterOut: emptyFilter(),
                msgFilterIn: emptyFilter(),
              };
            } else {
              currentEndpoint = null; // Ignore non-endpoint sections
            }
          }
        } else if (currentEndpoint) {
          const eqIndex = trimmed.indexOf('=');
          if (eqIndex === -1) return;
          const key = trimmed.slice(0, eqIndex).trim();
          // Strip inline comments from the value
          const value = stripComment(trimmed.slice(eqIndex + 1));

          if (key === 'AllowMsgIdOut') {
            currentEndpoint.msgFilterOut.mode = 'allow';
            currentEndpoint.msgFilterOut.ids = value.split(/\s+/).filter(Boolean).map(Number);
            currentEndpoint.msgFilterOpen = true;
          } else if (key === 'BlockMsgIdOut') {
            currentEndpoint.msgFilterOut.mode = 'block';
            currentEndpoint.msgFilterOut.ids = value.split(/\s+/).filter(Boolean).map(Number);
            currentEndpoint.msgFilterOpen = true;
          } else if (key === 'AllowMsgIdIn') {
            currentEndpoint.msgFilterIn.mode = 'allow';
            currentEndpoint.msgFilterIn.ids = value.split(/\s+/).filter(Boolean).map(Number);
            currentEndpoint.msgFilterOpen = true;
          } else if (key === 'BlockMsgIdIn') {
            currentEndpoint.msgFilterIn.mode = 'block';
            currentEndpoint.msgFilterIn.ids = value.split(/\s+/).filter(Boolean).map(Number);
            currentEndpoint.msgFilterOpen = true;
          } else {
            currentEndpoint.config[key] = value;
          }
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

      // Validate: if allow/block mode is active, must have at least one ID
      for (const ep of this.endpoints) {
        for (const [slot, label] of [[ep.msgFilterOut, 'Out'], [ep.msgFilterIn, 'In']]) {
          if (slot.mode !== 'none' && slot.ids.length === 0) {
            alert(`Endpoint "${ep.name}" has Msg ID ${label} filtering enabled but no IDs specified. Add at least one ID or set filtering to None.`);
            return;
          }
        }
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
      const msgFilterKeys = new Set(['AllowMsgIdOut', 'BlockMsgIdOut', 'AllowMsgIdIn', 'BlockMsgIdIn']);
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
            this.appendMsgFilterLines(sectionLines, currentEndpoint);
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
                sectionLines = [line]; // Buffer to hold lines for this section
                skipSection = false; // We're keeping this section
              } else {
                skipSection = true; // We're skipping this section (deleted endpoint)
              }
            } else {
              // Non-endpoint sections, just add them directly
              insideEndpointSection = false;
              currentEndpoint = null;
              skipSection = false;
              updatedConfigLines.push(line);
            }
          } else {
            insideEndpointSection = false;
            currentEndpoint = null;
            updatedConfigLines.push(line); // If no match, continue adding lines
          }
        } else if (insideEndpointSection && !skipSection) {
          const eqIndex = trimmed.indexOf('=');
          if (eqIndex !== -1) {
            const key = trimmed.slice(0, eqIndex).trim();
            // Drop old filter lines — re-emitted by appendMsgFilterLines
            if (msgFilterKeys.has(key)) return;
            if (key in currentEndpoint.config) {
              sectionLines.push(`${key} = ${currentEndpoint.config[key]}`);
            } else {
              sectionLines.push(line);
            }
          } else {
            // Preserve blank lines / comment-only lines inside a kept section
            if (!trimmed.startsWith('#')) {
              sectionLines.push(line);
            }
          }
        } else if (!insideEndpointSection && !skipSection) {
          // Outside of any endpoint section, keep the line as is
          updatedConfigLines.push(line);
        }
      });

      // Flush last section
      if (!skipSection && insideEndpointSection && currentEndpoint) {
        this.appendMsgFilterLines(sectionLines, currentEndpoint);
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
          this.appendMsgFilterLines(updatedConfigLines, endpoint);
          updatedConfigLines.push(''); // Add a blank line after the section
        }
      });

      return updatedConfigLines;
    },
    appendMsgFilterLines(lines, endpoint) {
      const { msgFilterOut, msgFilterIn } = endpoint;
      if (msgFilterOut.mode === 'allow' && msgFilterOut.ids.length > 0) {
        lines.push(`AllowMsgIdOut = ${msgFilterOut.ids.join(' ')}`);
      } else if (msgFilterOut.mode === 'block' && msgFilterOut.ids.length > 0) {
        lines.push(`BlockMsgIdOut = ${msgFilterOut.ids.join(' ')}`);
      }
      if (msgFilterIn.mode === 'allow' && msgFilterIn.ids.length > 0) {
        lines.push(`AllowMsgIdIn = ${msgFilterIn.ids.join(' ')}`);
      } else if (msgFilterIn.mode === 'block' && msgFilterIn.ids.length > 0) {
        lines.push(`BlockMsgIdIn = ${msgFilterIn.ids.join(' ')}`);
      }
    },
    getDefaultConfig(type) {
      switch (type) {
        case 'Udp':
        case 'UdpEndpoint':
          return { Mode: 'Normal', Address: '0.0.0.0', Port: 14550 };
        case 'Uart':
        case 'UartEndpoint':
          return { Device: '/dev/serial0', Baud: '115200', FlowControl: 'false' };
        case 'Tcp':
        case 'TcpEndpoint':
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
        isEditing: true,
        msgFilterOpen: false,
        msgFilterOut: emptyFilter(),
        msgFilterIn: emptyFilter(),
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
    toggleMsgFilter(index) {
      this.endpoints[index].msgFilterOpen = !this.endpoints[index].msgFilterOpen;
    },
    addMsgId(index, direction) {
      const filter = direction === 'out' ? this.endpoints[index].msgFilterOut : this.endpoints[index].msgFilterIn;
      filter.idError = '';
      const raw = String(filter.newId).trim();

      if (raw === '') {
        filter.idError = 'Please enter a message ID.';
        return;
      }
      const num = parseInt(raw, 10);
      if (isNaN(num) || num < 0) {
        filter.idError = 'ID must be a non-negative integer.';
        return;
      }
      if (filter.ids.includes(num)) {
        filter.idError = `ID ${num} is already in the list.`;
        return;
      }
      filter.ids.push(num);
      filter.ids.sort((a, b) => a - b);
      filter.newId = '';
    },
    removeMsgId(endpointIndex, direction, idIndex) {
      const filter = direction === 'out'
        ? this.endpoints[endpointIndex].msgFilterOut
        : this.endpoints[endpointIndex].msgFilterIn;
      filter.ids.splice(idIndex, 1);
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

/* ── Message Filtering ─────────────────────────────────────────── */

.msg-filter-section {
  margin-top: 10px;
  border-top: 1px solid var(--ark-color-black-shadow);
  padding-top: 8px;
}

.msg-filter-toggle {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
  color: var(--ark-color-black);
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  width: auto;
}

.msg-filter-toggle:hover {
  color: var(--ark-color-blue);
}

.msg-filter-toggle i {
  font-size: 11px;
  width: 12px;
}

.msg-filter-badge {
  display: inline-block;
  border-radius: 10px;
  padding: 1px 8px;
  font-size: 11px;
  font-weight: 600;
  margin-left: 4px;
  color: var(--ark-color-white);
  background-color: var(--ark-color-blue);
}

.msg-filter-badge.allow {
  background-color: var(--ark-color-green, #009650);
}

.msg-filter-badge.block {
  background-color: var(--ark-color-red, #c82828);
}

.msg-filter-body {
  margin-top: 10px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.msg-filter-direction-block {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 6px;
  background-color: rgba(0, 0, 0, 0.03);
  border: 1px solid var(--ark-color-black-shadow);
}

.msg-filter-direction-label {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 2px;
}

.direction-pill {
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 2px 7px;
  border-radius: 4px;
  color: var(--ark-color-white);
  flex-shrink: 0;
}

.direction-pill.out {
  background-color: var(--ark-color-blue, #0066cc);
}

.direction-pill.in {
  background-color: #7c3aed;
}

.direction-desc {
  font-size: 12px;
  color: #666;
  font-weight: normal;
}

.msg-filter-mode {
  display: flex;
  gap: 20px;
  align-items: center;
  flex-wrap: wrap;
}

.radio-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: normal;
  cursor: pointer;
  font-size: 13px;
}

.radio-label input[type="radio"] {
  width: auto;
  margin: 0;
  cursor: pointer;
}

.msg-id-area {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.msg-id-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  min-height: 30px;
  align-items: center;
}

.msg-id-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 12px;
  font-weight: 600;
  font-family: monospace;
}

.msg-id-tag.allow {
  background-color: rgba(0, 150, 80, 0.12);
  color: var(--ark-color-green, #009650);
  border: 1px solid rgba(0, 150, 80, 0.3);
}

.msg-id-tag.block {
  background-color: rgba(200, 40, 40, 0.1);
  color: var(--ark-color-red, #c82828);
  border: 1px solid rgba(200, 40, 40, 0.25);
}

.tag-remove {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 14px;
  line-height: 1;
  padding: 0;
  width: auto;
  color: inherit;
  opacity: 0.6;
}

.tag-remove:hover {
  opacity: 1;
}

.msg-id-empty {
  font-size: 12px;
  color: #888;
  font-style: italic;
}

.msg-id-input-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.msg-id-input {
  width: 160px !important;
  flex-shrink: 0;
}

.msg-id-add-btn {
  padding: 8px 14px;
  border: none;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border-radius: 4px;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  width: auto;
}

.msg-id-add-btn:hover {
  background-color: var(--ark-color-blue-hover);
}

.msg-id-error {
  color: red;
  font-size: 12px;
  margin: 0;
}
</style>
