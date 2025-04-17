<template>
  <div class="page-container">
    <!-- Header -->
    <h1 class="page-title">Network Connections Manager</h1>

    <!-- Navigation Tabs -->
    <div class="tabs-container" ref="tabsContainer">
      <button 
        class="tab-button"
        :class="{ 'active': activeSection === 'current' }"
        @click="activeSection = 'current'"
      >
        Connections
      </button>
      <button 
        class="tab-button"
        :class="{ 'active': activeSection === 'usage' }"
        @click="activeSection = 'usage'"
      >
        Data Usage
      </button>
      <button
        v-if="hasLteModem"
        class="tab-button"
        :class="{ 'active': activeSection === 'lte' }"
        @click="activeSection = 'lte'"
        data-tab="lte"
      >
        LTE Modem
      </button>
    </div>

    <!-- Tab Content Wrapper -->
    <div class="tab-content-wrapper">
      <!-- Connections Section -->
      <div v-if="activeSection === 'current'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">Connections</h2>
          <div class="header-actions">
            <button @click="fetchConnections" class="refresh-button">
              <i class="fas fa-sync-alt" :class="{ 'fa-spin': refreshingConnections }"></i>
              Refresh
            </button>
            <button @click="showAddConnectionForm" class="add-button">
              <i class="fas fa-plus"></i>
              Add Connection
            </button>
          </div>
        </div>

        <div class="table-container">
          <table class="connections-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Signal</th>
                <th>IP Address</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="connection in connections"
                :key="connection.name"
                :class="{ 'active-row': connection.active === 'yes' }"
              >
                <!-- Name -->
                <td>
                  <div class="connection-name">
                    <span class="icon-container" v-html="getConnectionIcon(connection.type, connection.mode)"></span>
                    <span>{{ connection.name }}</span>
                  </div>
                </td>
                <!-- Type -->
                <td class="capitalize">
                  {{ connection.type === 'wifi' && connection.mode === 'ap' ? 'wifi-hotspot' : connection.type }}
                </td>
                <!-- Signal -->
                <td>
                  <div v-if="connection.type !== 'ethernet'" class="signal-container">
                    <div class="signal-bar" :style="{ width: `${connection.signal}%` }" :class="getSignalClass(connection.signal)"></div>
                  </div>
                </td>
                <!-- IP address -->
                <td>{{ connection.ipAddress }}</td>
                <!-- Actions -->
                <td class="actions">
                  <button @click="editConnection(connection)" class="icon-button configure">
                    <i class="fas fa-cog"></i>
                  </button>
                  <button
                    @click="toggleConnection(connection)"
                    class="icon-button"
                    :class="connection.active === 'yes' ? 'disconnect' : 'connect'"
                  >
                    <i :class="connection.active === 'yes' ? 'fas fa-stop' : 'fas fa-play'"></i>
                  </button>
                  <button @click="deleteConnection(connection)" class="icon-button delete">
                    <i class="fas fa-trash"></i>
                  </button>
                </td>
              </tr>
              <tr v-if="connections.length === 0">
                <td colspan="6" class="empty-state">
                  <div class="empty-message">
                    <i class="fas fa-network-wired"></i>
                    <p>No connections found</p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Data Usage Section -->
      <div v-if="activeSection === 'usage'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">Data Usage</h2>
        </div>

        <div v-if="socketError" class="error-message-small">
          <i class="fas fa-exclamation-triangle"></i>
          <p>{{ socketError }}</p>
        </div>

        <!-- Loading spinner -->
        <div v-if="isLoadingUsageData" class="loading-container">
          <div class="spinner"></div>
          <p>Loading network data...</p>
        </div>
        <!-- Data -->
        <div v-else class="usage-container">
          <div v-if="usageData.length === 0" class="empty-state">
            <div class="empty-message">
              <i class="fas fa-chart-bar"></i>
              <p>Waiting for network data...</p>
            </div>
          </div>

          <div class="usage-details">
            <div
              v-for="(item, idx) in usageData"
              :key="item.name"
              class="usage-item"
              :class="{ 'expanded': expandedInterfaces[idx] }"
              @click="toggleInterface(idx)"
            >
              <!-- Always visible header with basic info -->
              <div class="usage-item-header">
                <div class="usage-info">
                  <span class="usage-name">{{ item.name }}</span>
                  <span class="usage-interface">({{ item.interface }})</span>
                  <span class="interface-type capitalize">{{ item.type }}</span>
                </div>
                <div class="usage-rates">
                  <span class="download-value">↓ {{ item.dataDown.toFixed(1) }}</span>
                  <span class="rate-separator">/</span>
                  <span class="upload-value">↑ {{ item.dataUp.toFixed(1) }}</span>
                  <span class="rate-unit">Mbps</span>
                  <i class="fas" :class="expandedInterfaces[idx] ? 'fa-chevron-up' : 'fa-chevron-down'"></i>
                </div>
              </div>

              <!-- Basic rate bars - always visible -->
              <div class="usage-bars-compact">
                <div class="rate-bar-container">
                  <div class="rate-bar-fill download"
                       :style="{ width: calculateBarWidth(item.dataDown) }"></div>
                </div>
                <div class="rate-bar-container">
                  <div class="rate-bar-fill upload"
                       :style="{ width: calculateBarWidth(item.dataUp) }"></div>
                </div>
              </div>

              <!-- Expanded details - only visible when expanded -->
              <div v-if="expandedInterfaces[idx]" class="usage-details-expanded">
                <!-- Connection details grid -->
                <div class="usage-details-grid">
                  <div v-if="item.ipAddress" class="usage-detail-item">
                    <span class="detail-label">IP Address:</span>
                    <span class="detail-value">{{ item.ipAddress }}</span>
                  </div>
                  <div v-if="item.type !== 'ethernet' && item.signal" class="usage-detail-item">
                    <span class="detail-label">Signal Strength:</span>
                    <span class="detail-value">
                      <div class="signal-container">
                        <div class="signal-bar" :style="{ width: `${item.signal}%` }" :class="getSignalClass(item.signal)"></div>
                      </div>
                    </span>
                  </div>
                  <div v-if="item.active !== undefined" class="usage-detail-item">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value" :class="item.active ? 'text-success' : ''">
                      {{ item.active ? 'Active' : 'Inactive' }}
                    </span>
                  </div>
                </div>

                <!-- Transfer statistics -->
                <div class="usage-statistics">
                  <div class="usage-stat-header">Transfer Statistics</div>
                  <div class="statistics-grid">
                    <div class="stat-item">
                      <div class="stat-label">Total Downloaded</div>
                      <div class="stat-value download-value">{{ formatBytes(item.rxBytes) }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">Total Uploaded</div>
                      <div class="stat-value upload-value">{{ formatBytes(item.txBytes) }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">RX Errors</div>
                      <div class="stat-value">{{ item.rxErrors }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">TX Errors</div>
                      <div class="stat-value">{{ item.txErrors }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">RX Dropped</div>
                      <div class="stat-value">{{ item.rxDropped }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">TX Dropped</div>
                      <div class="stat-value">{{ item.txDropped }}</div>
                    </div>
                  </div>
                </div>

                <!-- Packet statistics -->
                <div class="usage-packet-stats">
                  <div class="usage-stat-header">Packet Statistics</div>
                  <div class="packet-stats-grid">
                    <div class="stat-item">
                      <div class="stat-label">RX Packets</div>
                      <div class="stat-value">{{ item.rxPackets?.toLocaleString() || '0' }}</div>
                    </div>
                    <div class="stat-item">
                      <div class="stat-label">TX Packets</div>
                      <div class="stat-value">{{ item.txPackets?.toLocaleString() || '0' }}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="usageData.length === 0" class="empty-state">
              <div class="empty-message">
                <i class="fas fa-chart-bar"></i>
                <p>No data usage information available</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Connection Form Dialog -->
      <div v-if="showConnectionForm" class="dialog-overlay">
        <div class="dialog-container">
          <div class="dialog-header">
            <h3 class="dialog-title">{{ isEditingConnection ? 'Edit' : 'Add' }} Connection</h3>
            <button @click="closeConnectionForm" class="close-button">
              <i class="fas fa-times"></i>
            </button>
          </div>

          <div class="dialog-content">
            <div v-if="!newConnection.type" class="connection-type-selector">
              <div class="connection-type-title">Select Connection Type</div>
                <div class="connection-type-options">
                  <button
                    @click="selectConnectionType('wifi')"
                    class="connection-type-button"
                  >
                    <i class="fas fa-wifi"></i>
                    <span>WiFi</span>
                  </button>
                  <button
                    @click="selectConnectionType('ethernet')"
                    class="connection-type-button"
                  >
                    <i class="fas fa-network-wired"></i>
                    <span>Ethernet</span>
                  </button>
                  <button
                    v-if="hasLteModem"
                    @click="selectConnectionType('lte')"
                    class="connection-type-button"
                    :class="{'disabled': hasExistingLteConnection}"
                    :disabled="hasExistingLteConnection"
                  >
                    <i class="fas fa-signal"></i>
                    <span>LTE / Cellular</span>
                  </button>
              </div>
            </div>

            <!-- WiFi Connection Form -->
            <form v-if="newConnection.type === 'wifi'" @submit.prevent="saveConnection" class="connection-form">
              <div class="form-group">
                <label for="wifi-mode">Connection Mode:</label>
                <div class="radio-group">
                  <label class="radio-option" :class="{ 'disabled': isEditingConnection }">
                    <input type="radio" v-model="newConnection.mode" value="infrastructure" id="mode-client" :disabled="isEditingConnection">
                    <span>Station (Client)</span>
                  </label>
                  <label class="radio-option" :class="{ 'disabled': isEditingConnection }">
                    <input type="radio" v-model="newConnection.mode" value="ap" id="mode-ap" :disabled="isEditingConnection">
                    <span>Access Point (Hotspot)</span>
                  </label>
                </div>
              </div>

              <!-- Add warning message for duplicate SSID -->
              <div v-if="isDuplicateConnection" class="duplicate-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <span>A connection with this SSID already exists.</span>
              </div>

              <!-- Available WiFi Networks Section (only for infrastructure mode) -->
              <div v-if="newConnection.mode === 'infrastructure' && !isEditingConnection" class="wifi-scan-container">
                <div class="wifi-scan-header">
                  <h3>Available Networks</h3>
                  <button type="button" @click="scanWifiFromConnectionForm" class="wifi-scan-button">
                    <i class="fas fa-sync-alt" :class="{ 'fa-spin': scanning }"></i>
                    Rescan
                  </button>
                </div>

                <div class="wifi-networks-list">
                  <div v-if="scanning && availableWifiNetworks.length === 0" class="scanning-overlay">
                    <div class="spinner"></div>
                    <p>Scanning for networks...</p>
                  </div>

                  <div v-if="availableWifiNetworks.length === 0 && !scanning" class="empty-networks">
                    <i class="fas fa-wifi"></i>
                    <p>No WiFi networks found</p>
                  </div>

                  <div
                    v-for="network in availableWifiNetworks"
                    :key="network.ssid"
                    class="wifi-network-item form-wifi-item"
                    :class="{ 'selected': newConnection.ssid === network.ssid }"
                    @click="selectWifiNetwork(network)"
                  >
                    <div class="wifi-info">
                      <i class="fas fa-wifi" :class="getSignalClass(network.signal)"></i>
                      <div class="wifi-details">
                        <span class="wifi-name">{{ network.ssid }}</span>
                        <span v-if="network.secured" class="security-badge">Secured</span>
                      </div>
                    </div>

                    <div class="wifi-signal">
                      <div class="signal-container">
                        <div class="signal-bar" :style="{ width: `${network.signal}%` }" :class="getSignalClass(network.signal)"></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Manual SSID input (for both modes) -->
              <div class="form-group">
                <label for="wifi-ssid">SSID:</label>
                <input type="text" id="wifi-ssid" v-model="newConnection.ssid" required :readonly="isEditingConnection" :class="{ 'readonly-input': isEditingConnection }">
              </div>

              <div class="form-group">
                <label for="wifi-password">Password:</label>
                <div class="password-input">
                  <input
                    :type="passwordVisible ? 'text' : 'password'"
                    id="wifi-password"
                    v-model="newConnection.password"
                    :required="newConnection.mode === 'ap' || selectedNetworkSecured"
                  >
                  <button
                    type="button"
                    @click="togglePasswordVisibility"
                    class="password-toggle"
                  >
                    <i :class="passwordVisible ? 'fas fa-eye-slash' : 'fas fa-eye'"></i>
                  </button>
                </div>
              </div>

              <div v-if="newConnection.type === 'wifi'" class="form-group">
                <span class="label-text">Auto-Connect:</span>
                <div class="toggle-switch">
                  <input type="checkbox" id="wifi-autoconnect"
                         :checked="newConnection.autoconnect === 'yes'"
                         @change="newConnection.autoconnect = $event.target.checked ? 'yes' : 'no'">
                  <label for="wifi-autoconnect" class="toggle-slider"></label>
                </div>
              </div>

              <div class="form-buttons">
                <button type="button" @click="closeConnectionForm" class="cancel-button">Cancel</button>
                <button
                  type="submit"
                  class="submit-button"
                  :disabled="isDuplicateConnection"
                  :class="{ 'disabled-button': isDuplicateConnection }"
                >
                  {{ isEditingConnection ? 'Update' : 'Add' }} Connection
                </button>
              </div>
            </form>

            <!-- Ethernet Connection Form -->
            <form v-if="newConnection.type === 'ethernet'" @submit.prevent="saveConnection" class="connection-form">
              <div class="form-group">
                <label for="ethernet-name">Connection Name:</label>
                <input type="text" id="ethernet-name" v-model="newConnection.name" required>
              </div>

              <!-- Add warning message for duplicate name -->
              <div v-if="isDuplicateConnection" class="duplicate-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <span>A connection with this name already exists.</span>
              </div>

              <div class="form-group">
                <label for="ethernet-method">IP Configuration:</label>
                <select id="ethernet-method" v-model="newConnection.ipMethod">
                  <option value="auto">Automatic (DHCP)</option>
                  <option value="manual">Manual</option>
                </select>
              </div>

              <div v-if="newConnection.ipMethod === 'manual'" class="manual-ip-section">
                <div class="form-group">
                  <label for="ethernet-ip">IP Address:</label>
                  <input type="text" id="ethernet-ip" v-model="newConnection.ipAddress" placeholder="192.168.1.100">
                </div>
              </div>

              <div class="form-buttons">
                <button type="button" @click="closeConnectionForm" class="cancel-button">Cancel</button>
                <button
                  type="submit"
                  class="submit-button"
                  :disabled="isDuplicateConnection"
                  :class="{ 'disabled-button': isDuplicateConnection }"
                >
                  {{ isEditingConnection ? 'Update' : 'Add' }} Connection
                </button>
              </div>
            </form>

            <!-- LTE Connection Form -->
            <form v-if="newConnection.type === 'lte'" @submit.prevent="saveConnection" class="connection-form">
              <div class="form-group">
                <label for="lte-name">Connection Name:</label>
                <input type="text" id="lte-name" v-model="newConnection.name" required>
              </div>

              <div class="form-group">
                <label for="lte-apn">APN (Access Point Name):</label>
                <input type="text" id="lte-apn" v-model="newConnection.apn" required placeholder="e.g., fast.t-mobile.com">
              </div>

              <div v-if="lteStatus.suggestedApn" class="apn-suggestion">
                <i class="fas fa-info-circle"></i>
                <span>Suggested APN for your carrier: <strong>{{ lteStatus.suggestedApn }}</strong></span>
                <button type="button" @click="useSuggestedApn" class="use-suggested-button">Use Suggested</button>
              </div>

              <div class="form-group">
                <span class="label-text">Auto-Connect:</span>
                <div class="toggle-switch">
                  <input type="checkbox" id="lte-autoconnect"
                         :checked="newConnection.autoconnect === 'yes'"
                         @change="newConnection.autoconnect = $event.target.checked ? 'yes' : 'no'">
                  <label for="lte-autoconnect" class="toggle-slider"></label>
                </div>
              </div>

              <div class="form-buttons">
                <button type="button" @click="closeConnectionForm" class="cancel-button">Cancel</button>
                <button
                  type="submit"
                  class="submit-button"
                  :disabled="isDuplicateConnection"
                  :class="{ 'disabled-button': isDuplicateConnection }"
                >
                  {{ isEditingConnection ? 'Update' : 'Add' }} Connection
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>

      <!-- LTE Modem Section -->
      <div v-if="activeSection === 'lte'" class="section-container">
        <div class="section-header">
          <h2 class="section-title">LTE Modem</h2>
          <div class="header-actions">
            <button @click="refreshLteStatus" class="refresh-button" :disabled="refreshingLte">
              <i class="fas fa-sync-alt" :class="{ 'fa-spin': refreshingLte }"></i>
              Refresh
            </button>
          </div>
        </div>

        <div v-if="lteStatus.status === 'not_found'" class="error-container">
          <i class="fas fa-exclamation-triangle"></i>
          <span>No LTE modem detected. Please check your hardware connection.</span>
        </div>

        <div v-else-if="lteStatus.status === 'error'" class="error-container">
          <i class="fas fa-exclamation-triangle"></i>
          <span>{{ lteStatus.message || 'Error retrieving LTE status' }}</span>
        </div>

        <div v-else class="lte-content">
          <!-- Main status card with signal strength -->
          <div class="lte-status-header-card">
            <div class="status-header-content">
              <div class="status-info">
                <div class="status-badge" :class="lteStatus.state">
                  {{ lteStatus.state || 'unknown' }}
                </div>
                <div v-if="lteStatus.registration === 'roaming'" class="roaming-badge">
                  Roaming
                </div>
              </div>

              <div class="signal-info">
                <div class="signal-label">
                  <span>Signal Strength</span>
                  <span>{{ lteStatus.signal || 0 }}%</span>
                </div>
                <div class="signal-container wide">
                  <div class="signal-bar"
                       :style="{ width: `${lteStatus.signal || 0}%` }"
                       :class="getSignalClass(lteStatus.signal)">
                  </div>
                </div>
              </div>

              <div class="apn-info">
                <span class="info-label">APN:</span>
                <span class="info-value">{{ lteStatus.apn || lteStatus.initialApn || lteStatus.suggestedApn || '-' }}</span>
              </div>

            </div>
          </div>

          <!-- Two-column grid for top info cards -->
          <div class="lte-info-top-grid">
            <!-- Carrier Information Card -->
            <div class="lte-info-card">
              <h3 class="card-title carrier-title">Carrier Information</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Network Operator:</span>
                  <span class="info-value">
                    {{ lteStatus.operatorName || '-' }}
                    <span class="info-secondary" v-if="lteStatus.operatorId">({{ lteStatus.operatorId }})</span>
                  </span>
                </div>

                <div class="info-item">
                  <span class="info-label">SIM Operator:</span>
                  <span class="info-value">
                    {{ lteStatus.simOperatorName || '-' }}
                    <span class="info-secondary" v-if="lteStatus.simOperatorId">({{ lteStatus.simOperatorId }})</span>
                  </span>
                </div>

                <div class="info-item">
                  <span class="info-label">Registration:</span>
                  <span class="info-value capitalize">{{ lteStatus.registration || '-' }}</span>
                </div>

                <div class="info-item">
                  <span class="info-label">SIM Status:</span>
                  <span class="info-value">{{ lteStatus.simActive === 'yes' ? 'Active' : 'Inactive' }}</span>
                </div>

                <div class="info-item" v-if="lteStatus.simImsi">
                  <span class="info-label">SIM IMSI:</span>
                  <span class="info-value monospace">{{ lteStatus.simImsi }}</span>
                </div>
              </div>
            </div>

            <!-- Hardware Information Card -->
            <div class="lte-info-card">
              <h3 class="card-title hardware-title">Modem Hardware</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Manufacturer:</span>
                  <span class="info-value">{{ lteStatus.manufacturer || '-' }}</span>
                </div>

                <div class="info-item">
                  <span class="info-label">Model:</span>
                  <span class="info-value">{{ lteStatus.model || '-' }}</span>
                </div>

                <div class="info-item">
                  <span class="info-label">IMEI:</span>
                  <span class="info-value monospace">{{ lteStatus.imei || '-' }}</span>
                </div>

                <div class="info-item">
                  <span class="info-label">Firmware:</span>
                  <span class="info-value monospace">{{ lteStatus.firmwareRevision ? lteStatus.firmwareRevision.split(' ')[0] : '-' }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Connection Details Card -->
          <div class="lte-info-card lte-connection-card">
            <h3 class="card-title connection-title">{{ lteStatus.state === 'connected' ? 'Connection Details' : 'Connection Status' }}</h3>

            <div v-if="lteStatus.state === 'connected' && lteStatus.interface">
              <!-- 3-column grid with consolidated information -->
              <div class="connection-info-grid">
                <div class="info-item">
                  <span class="info-label">Interface:</span>
                  <span class="info-value monospace">
                    {{ lteStatus.interface }}
                    <span :class="lteStatus.interfaceState === 'up' ? 'status-tag status-up' : 'status-tag status-down'">
                      {{ lteStatus.interfaceState === 'up' ? 'up' : 'down' }}
                    </span>
                  </span>
                </div>

                <div class="info-item">
                  <span class="info-label">MTU:</span>
                  <span class="info-value">{{ lteStatus.mtu || '1500' }}</span>
                </div>

                <!-- First DNS server in the grid -->
                <div class="info-item" v-if="lteStatus.dns && lteStatus.dns.length > 0">
                  <span class="info-label">Primary DNS:</span>
                  <span class="info-value monospace dns-value">
                    {{ lteStatus.dns[0] }}
                  </span>
                </div>

                 <div class="info-item">
                  <span class="info-label">IP Address:</span>
                  <span class="info-value monospace">
                    {{ lteStatus.ipAddress || '-' }}
                    <span v-if="lteStatus.ipMethod" class="status-tag status-method">
                      {{ lteStatus.ipMethod }}
                    </span>
                  </span>
                </div>

                <div class="info-item">
                  <span class="info-label">Gateway:</span>
                  <span class="info-value monospace">{{ lteStatus.gateway || '-' }}</span>
                </div>

                <!-- Second DNS server in the grid (if available) -->
                <div class="info-item" v-if="lteStatus.dns && lteStatus.dns.length > 1">
                  <span class="info-label">Secondary DNS:</span>
                  <span class="info-value monospace dns-value">
                    {{ lteStatus.dns[1] }}
                  </span>
                </div>
              </div>
            </div>

            <div v-else class="not-connected">
              <span>Not currently connected</span>
            </div>
          </div>
          <!-- End Connection Details Card -->
        </div>
      </div>
      <!-- End LTE Modem Section -->
    </div>
  </div>
</template>

<script>
import ConnectionsService from '../services/ConnectionsService';
import io from 'socket.io-client';

export default {
  data() {
    return {
      activeSection: 'current',
      refreshingConnections: false,
      scanning: false,
      availableWifiNetworks: [],

      // Network usage data
      usageData: [],
      expandedInterfaces: [],  // Track expanded/collapsed state of each interface
      socketError: null,
      statsSocket: null,
      isLoadingUsageData: true,
      
      // Connection form
      showConnectionForm: false,
      isEditingConnection: false,
      passwordVisible: false,
      selectedNetworkSecured: false,
      
      // LTE specific
      lteStatus: { status: 'loading' },
      refreshingLte: false,

      // connections []
      // - name
      // - type
      // - device
      // - autoconnect
      // - active
      // - ssid
      // - mode
      // - signal
      connections: [],

      newConnection: {
        name: '',
        type: '', // wifi, ethernet
        autoconnect: 'yes',
        // WiFi specific
        ssid: '',
        password: '',
        mode: 'infrastructure', // infrastructure, ap, bridge
        // Ethernet specific
        ipMethod: 'auto', // auto, static
        ipAddress: '',
      },
    };
  },
  
  computed: {
    // Calculate the maximum data rate for scaling the usage bars
    maxDataRate() {
      if (this.usageData.length === 0) return 100;
      
      let max = 0;
      this.usageData.forEach(item => {
        max = Math.max(max, item.dataDown, item.dataUp);
      });
      
      return max > 0 ? max : 100;
    },
    isDuplicateConnection() {

      if (this.newConnection.type === 'wifi') {
        if (!this.newConnection.ssid || this.isEditingConnection) {
          return false;
        }
        return this.connections.some(connection =>
          connection.ssid === this.newConnection.ssid);

      } else if (this.newConnection.type === 'ethernet') {
        if (!this.newConnection.name || this.isEditingConnection) {
          return false;
        }
        return this.connections.some(connection =>
          connection.name === this.newConnection.name);
      }
      return false;
    },
    hasLteModem() {
      // Check if we have a valid lteStatus that isn't an error state
      return this.lteStatus && this.lteStatus.model && this.lteStatus.model.trim() !== '';
    },
    hasExistingLteConnection() {
      return this.connections.some(connection => connection.type === 'lte');
    },
  },
  
  async mounted() {
    // Initial data fetch
    await this.fetchAll();
    // Also fetch LTE status to determine if we should show LTE options
    await this.fetchLteStatus();
    
    // Connect to socket if starting on usage tab
    if (this.activeSection === 'usage') {
      this.connectUsageSocket();
    }
  },
  
  beforeUnmount() {
    // Make sure socket is disconnected
    this.disconnectUsageSocket();
  },

  watch: {
    // Watch section changes for socket connections
    activeSection(newSection, oldSection) {
      if (newSection === 'usage') {
        this.isLoadingUsageData = true;
        // Connect socket when viewing usage tab
        this.socketError = null;  // Clear any previous errors
        this.connectUsageSocket();
      } else if (oldSection === 'usage') {
        // Disconnect socket when leaving usage tab
        this.disconnectUsageSocket();
        this.socketError = null;  // Clear errors when leaving tab
      }

      // Fetch the data for the new active section
      this.fetchSectionData(newSection, true);
    },
  },
  
  methods: {
    // --- Data Fetching ---
    
    // Helper method to fetch only data needed for current section
    fetchSectionData(section) {
      switch (section) {
        case 'current':
          this.fetchConnections();
          break;
        case 'usage':
          // For usage tab, we only need to connect to WebSocket
          // No REST API call needed - data comes via WebSocket
          break;
        case 'lte':
          this.fetchLteStatus();
          break;
      }
    },

    async fetchAll() {
      try {
        this.fetchSectionData(this.activeSection);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    },
    
    async fetchConnections() {
      try {
        this.refreshingConnections = true
        const response = await ConnectionsService.getConnections();

        // Simply replace the array with new data
        // This is simpler and less error-prone than partial updates
        this.connections = response.data;
      } catch (error) {
        console.error('Failed to fetch connections:', error);
      } finally {
        this.refreshingConnections = false
      }
    },

    refreshConnectionsWithDelay(delayMs = 1000) {
      this.refreshingConnections = true;
      setTimeout(async () => {
        // Refresh connections
        await this.fetchConnections();
      }, delayMs);
    },

    async scanWifi() {
      this.scanning = true;
      try {
        const response = await ConnectionsService.scanWifiNetworks();
        // Filter out hidden networks (those with -- as the name)
        this.availableWifiNetworks = response.data.filter(network => network.ssid !== '--');
      } catch (error) {
        console.error('Failed to scan WiFi networks:', error);
      } finally {
        this.scanning = false;
      }
    },

    // Explicitly trigger a WiFi scan from the connection form
    async scanWifiFromConnectionForm() {
      // Always show animation when explicitly requested
      this.scanning = true;

      try {
        const response = await ConnectionsService.scanWifiNetworks();
        // Filter out hidden networks (those with -- as the name)
        this.availableWifiNetworks = response.data.filter(network => network.ssid !== '--');
      } catch (error) {
        console.error('Failed to scan WiFi networks:', error);
      } finally {
        this.scanning = false;
      }
    },
    
    // Select a WiFi network from the scan list
    selectWifiNetwork(network) {
      this.newConnection = {
        ...this.newConnection,
        name: network.ssid,
        ssid: network.ssid,
        type: 'wifi',
        mode: 'infrastructure'
      };
      this.selectedNetworkSecured = network.secured;

      // If the network is secured, focus the password field
      if (network.secured) {
        this.$nextTick(() => {
          document.getElementById('wifi-password').focus();
        });
      }
    },

    connectUsageSocket() {
      try {
        // Close existing connection if any
        this.disconnectUsageSocket();

        this.statsSocket = io(process.env.VUE_APP_SOCKET_URL, {
          path: '/socket.io/network-stats',
          transports: ['websocket'],
          reconnectionAttempts: 5,
          reconnectionDelay: 1000
        });

        // Handle connection events
        this.statsSocket.on('connect', () => {
          console.log('Network stats Socket.IO connection established!', this.statsSocket.id);

          // Clear any previous error
          this.socketError = null;
        });

        // Handle real-time data updates
        this.statsSocket.on('network_stats_update', (data) => {
          console.log(`Received network stats update with ${data ? data.length : 0} interfaces`);

          if (!data || !Array.isArray(data)) {
            console.error('Invalid network stats data format:', data);
            return;
          }

          // Process the data directly
          this.processNetworkStatsData(data);
        });

        // Handle connection errors
        this.statsSocket.on('connect_error', (error) => {
          console.error('Socket connection error:', error);
          this.socketError = `Connection error: ${error.message}`;
        });

        this.statsSocket.on('disconnect', (reason) => {
          console.log('Socket disconnected:', reason);
          if (this.activeSection === 'usage') {
            this.socketError = `WebSocket disconnected. Reconnecting...`;
          }
        });
      } catch (error) {
        console.error('Error in connectUsageSocket:', error);
        this.socketError = `WebSocket error: ${error.message}`;
      }
    },

    disconnectUsageSocket() {
      if (this.statsSocket) {
        console.log('Disconnecting from network stats socket:', this.statsSocket.id);

        // Remove all event listeners to prevent memory leaks
        this.statsSocket.off('connect');
        this.statsSocket.off('disconnect');
        this.statsSocket.off('connect_error');
        this.statsSocket.off('network_stats_update');

        // Disconnect the socket
        this.statsSocket.disconnect();

        // Clear the reference
        this.statsSocket = null;
        console.log('Socket disconnected and reference cleared');
      }
    },

    processNetworkStatsData(data) {
      if (!data || !Array.isArray(data)) {
        console.error('Invalid network stats data format:', data);
        return;
      }

      console.log(`Processing: ${data.length} interfaces`);

      this.isLoadingUsageData = false;

      try {
        // Create arrays to hold the processed data
        const processedData = [];

        // Process each interface
        for (let i = 0; i < data.length; i++) {
          const d = data[i];

          // Skip invalid entries
          if (!d || !d.interface) {
            console.warn(`Skipping invalid interface data at index ${i}`);
            continue;
          }

          // Process the values
          const downRate = parseFloat(d.rxRateMbps) || 0;
          const upRate = parseFloat(d.txRateMbps) || 0;

          // Create the processed interface object
          const processedInterface = {
            name: d.name || d.interface || 'Unknown',
            interface: d.interface,
            type: d.type || 'unknown',
            ipAddress: d.ipAddress || '',
            active: d.active || false,
            rxBytes: parseInt(d.rxBytes) || 0,
            txBytes: parseInt(d.txBytes) || 0,
            dataDown: parseFloat(downRate.toFixed(2)),
            dataUp: parseFloat(upRate.toFixed(2)),
            totalData: parseFloat((downRate + upRate).toFixed(2)),
            rxErrors: parseInt(d.rxErrors) || 0,
            rxDropped: parseInt(d.rxDropped) || 0,
            txErrors: parseInt(d.txErrors) || 0,
            txDropped: parseInt(d.txDropped) || 0,
            rxPackets: parseInt(d.rxPackets) || 0,
            txPackets: parseInt(d.txPackets) || 0,
            signal: parseInt(d.signal) || 0
          };

          processedData.push(processedInterface);
        }

        // Initialize expanded state array if needed
        if (this.expandedInterfaces.length !== processedData.length) {
          // Keep existing expanded states when possible
          const newExpandedState = new Array(processedData.length).fill(false);
          
          // Preserve expanded state for interfaces that remain
          if (this.usageData.length > 0) {
            processedData.forEach((newInterface, index) => {
              // Look for this interface in previous data to preserve expand state
              const existingIndex = this.usageData.findIndex(
                oldInterface => oldInterface.interface === newInterface.interface
              );
              if (existingIndex >= 0 && existingIndex < this.expandedInterfaces.length) {
                newExpandedState[index] = this.expandedInterfaces[existingIndex];
              }
            });
          }
          
          this.expandedInterfaces = newExpandedState;
        }

        // Data is already sorted by the server (active first, then by bytes)
        this.usageData = processedData;

        console.log(`Updated UI: usageData now has ${this.usageData.length} interfaces`);
        if (this.usageData.length > 0) {
          console.log(`First UI item: ${this.usageData[0].name}, Active: ${this.usageData[0].active}, Down: ${this.usageData[0].dataDown}, Up: ${this.usageData[0].dataUp}`);
        }
      } catch (error) {
        console.error('Error processing network data:', error);
      }
    },
    
    // Toggle expanded/collapsed state of an interface
    toggleInterface(index) {
      if (index >= 0 && index < this.expandedInterfaces.length) {
        // In Vue 3, reactive arrays can be directly modified
        const newExpandedInterfaces = [...this.expandedInterfaces];
        newExpandedInterfaces[index] = !newExpandedInterfaces[index];
        this.expandedInterfaces = newExpandedInterfaces;
      }
    },

    calculateBarWidth(rate) {
      // For zero values, show empty bar
      if (rate <= 0) return '0%';

      // Define max scale for 100% width (10Mbps is full width)
      const MAX_RATE = 10;

      // Calculate percentage with cap at 100%
      const percentage = Math.min(100, (rate / MAX_RATE) * 100);

      return `${percentage}%`;
    },

    // Format bytes to human-readable format
    formatBytes(bytes, decimals = 2) {
      if (bytes === 0) return '0 Bytes';

      const k = 1024;
      const dm = decimals < 0 ? 0 : decimals;
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];

      const i = Math.floor(Math.log(bytes) / Math.log(k));

      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    getSignalClass(strength) {
      if (strength === undefined || strength === null) return '';
      if (strength >= 70) return 'signal-strong';
      if (strength >= 40) return 'signal-medium';
      if (strength > 0) return 'signal-weak';

      return 'signal-none'
    },

    async fetchLteStatus() {
      this.refreshingLte = true;

      try {
        const response = await ConnectionsService.getLteStatus();

        // Put whole response into our data object
        this.lteStatus = response.data;

      } catch (error) {
        console.error('Failed to fetch LTE status:', error);
        this.lteStatus = { status: 'error', message: error.message || 'Failed to fetch LTE status' };
      } finally {
        this.refreshingLte = false;
      }
    },
    
    async refreshLteStatus() {
      this.refreshingLte = true;
      await this.fetchLteStatus();
      this.refreshingLte = false;
    },

    useSuggestedApn() {
      if (this.lteStatus && this.lteStatus.suggestedApn) {
        this.newConnection.apn = this.lteStatus.suggestedApn;
      }
    },
    
    async toggleConnection(connection) {
      try {
        if (connection.active === 'yes') {
          await ConnectionsService.disconnectConnection(connection.name);
        } else {
          await ConnectionsService.connectConnection(connection.name);
        }
        
        this.refreshConnectionsWithDelay();
      } catch (error) {
        console.error('Failed to toggle connection:', error);
      }
    },
    
    async editConnection(connection) {
      this.isEditingConnection = true;
      
      // Clone the connection to avoid modifying the original
      this.newConnection = {
        name: connection.name,
        type: connection.type,
        autoconnect: connection.autoconnect
      };
      
      if (connection.type === 'wifi') {
        this.newConnection.ssid = connection.ssid || '';
        this.newConnection.password = '';
        this.newConnection.mode = connection.mode || 'infrastructure';

      } else if (connection.type === 'ethernet') {
        this.newConnection.ipMethod = connection.ipMethod || 'auto';
        this.newConnection.ipAddress = connection.ipAddress || '';
      } else if (connection.type === 'lte') {
        // For LTE, fetch the current APN
        this.newConnection.apn = connection.apn || '';

        // If we don't have the APN, try to get it from the LTE status
        if (!this.newConnection.apn && this.lteStatus && this.lteStatus.apn) {
          this.newConnection.apn = this.lteStatus.apn;
        }
      }
      
      this.showConnectionForm = true;
    },
    
    async deleteConnection(connection) {
      if (!confirm(`Are you sure you want to delete the connection "${connection.name}"?`)) {
        return;
      }
      
      try {
        await ConnectionsService.deleteConnection(connection.name);
        this.refreshConnectionsWithDelay();
      } catch (error) {
        console.error('Failed to delete connection:', error);
      }
    },
    
    // --- Connection Form Management ---
    showAddConnectionForm() {
      this.showConnectionForm = true;
      this.isEditingConnection = false;
      this.resetNewConnection();
      this.selectedNetworkSecured = false;
    },
    
    selectConnectionType(type) {
      this.resetNewConnection();
      this.newConnection.type = type;
      
      // Set default values based on connection type
      if (type === 'wifi') {
        this.newConnection.mode = 'infrastructure';
        // Trigger a scan immediately when selecting WiFi type
        this.scanWifiFromConnectionForm();
      } else if (type === 'ethernet') {
        this.newConnection.name = 'Ethernet Connection';
      } else if (type === 'lte') {
        this.newConnection.name = 'LTE Connection';
        // Fetch LTE status to get suggested APN if not already loaded
        if (!this.lteStatus || !this.lteStatus.suggestedApn) {
          this.fetchLteStatus();
        }
      }
    },
    
    resetNewConnection() {
      this.newConnection = {
        name: '',
        type: '',
        autoconnect: 'yes',
        
        // WiFi specific
        ssid: '',
        password: '',
        mode: 'infrastructure',
        
        // Ethernet specific
        ipMethod: 'auto',
        ipAddress: '',

        // LTE specific
        apn: '',
      };
    },
    
    async saveConnection() {
      try {
        const connection = { ...this.newConnection };
        
        if (this.isEditingConnection) {
          await ConnectionsService.updateConnection(connection.name, connection);
        } else {
          await ConnectionsService.createConnection(connection);
        }
        
        // Close form and refresh data
        this.closeConnectionForm();
        this.refreshConnectionsWithDelay();

      } catch (error) {
        console.error('Failed to save connection:', error);
        alert('Failed to save connection. Please check your settings and try again.');
      }
    },
    
    closeConnectionForm() {
      this.showConnectionForm = false;
      this.isEditingConnection = false;
    },
    
    togglePasswordVisibility() {
      this.passwordVisible = !this.passwordVisible;
    },
    
    // --- Helper Methods ---
    getConnectionIcon(type, mode) {
      if (type === 'wifi') {
        if (mode === 'ap') {
          return '<i class="fas fa-tower-broadcast"></i>';
        } else {
          return '<i class="fas fa-wifi"></i>';
        }
      } else if (type === 'ethernet') {
        return '<i class="fas fa-network-wired"></i>';
      } else if (type === 'lte') {
        return '<i class="fas fa-signal"></i>';
      }
      
      return '<i class="fas fa-question-circle"></i>';
    }
  }
};
</script>

<style scoped>

/* Layout */
.page-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 1200px;
  min-width: 800px;
  margin: 0 auto;
  padding: 20px;
  gap: 20px;
  position: relative;
  box-sizing: border-box;
  overflow-x: hidden;
  height: 100%;
  max-height: 100vh;
}

/* Add a container for the tabs to ensure consistent width */
.tab-content-wrapper {
  width: 100%;
  min-width: 100%;
  position: relative;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  overflow: auto;
}

/* Ensure all section containers have a proper width */
.section-container {
  width: 100%;
  transition: opacity 0.2s ease;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  background-color: var(--ark-color-white);
  border-radius: 8px;
  padding: 20px;
  box-sizing: border-box;
  min-height: auto;
  overflow-y: auto;  /* Enable vertical scrolling */
  overflow-x: hidden; /* Prevent horizontal scrolling */
  display: flex;
  flex-direction: column;
  position: relative;
  min-width: 100%; /* Ensure consistent width */
  max-width: 100%; /* Prevent expanding beyond container */
}

/* Add smooth transitions for data updates */
.table-container,
.connections-table tbody tr,
.lte-info-card,
.usage-item {
  transition: all 0.2s ease;
}

.header-actions {
  display: flex;
  background: none;
  padding: 0;
  gap: 10px;
  align-items: center;
}

.page-title {
  font-size: 1.8rem;
  font-weight: bold;
  color: var(--ark-color-black);
  margin: 0 0 16px 0;
  text-align: center;
}

.refresh-button {
  display: flex;
  align-items: center;
  gap: 6px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  padding: 8px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background-color 0.2s;
}

.refresh-button:hover {
  background-color: rgba(52, 152, 219, 0.8);
}


.fa-spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

/* Tabs */
.tabs-container {
  display: grid;
  grid-template-columns: repeat(4, 1fr); /* Fixed 4 equal columns */
  gap: 8px;
  width: 100%;
  margin-bottom: 16px;
  position: sticky;
  top: 0;
  z-index: 100;
  background-color: var(--ark-color-white);
  padding: 8px 0;
  box-sizing: border-box;
  min-width: 100%;
}

.tab-button {
  padding: 12px;
  background-color: var(--ark-color-white);
  border: none;
  border-radius: 8px;
  color: var(--ark-color-black);
  font-weight: 500;
  transition: background-color 0.2s, color 0.2s; /* Only transition color and background */
  cursor: pointer;
  box-shadow: 0 2px 4px var(--ark-color-black-shadow);
  white-space: nowrap; /* Prevent text wrapping which causes size changes */
  text-overflow: ellipsis; /* Handle overflow text */
  overflow: hidden;
  text-align: center;
  box-sizing: border-box;
  height: 44px; /* Fixed height */
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%; /* Take full width of grid cell */
}

.tab-button:hover {
  background-color: var(--ark-color-black-shadow);
}

.tab-button.active {
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
}

/* Remove duplicate section-container rule */

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.section-title {
  font-size: 1.3rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
}

.add-button {
  display: flex;
  align-items: center;
  gap: 6px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  padding: 8px 12px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background-color 0.2s;
}

.add-button:hover {
  background-color: var(--ark-color-green-hover);
}

.table-container {
  display: flex;
  flex-direction: column;
  flex: 1; /* Take available space */
  overflow-x: auto;
  overflow-y: auto;
  max-height: none; /* Remove fixed max-height */
  border-radius: 4px;
  border: 1px solid var(--ark-color-black-shadow);
  scrollbar-width: thin;
  scrollbar-color: var(--ark-color-black-shadow) transparent;
}

.table-container::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

.table-container::-webkit-scrollbar-track {
  background: transparent;
}

.table-container::-webkit-scrollbar-thumb {
  background-color: var(--ark-color-black-shadow);
  border-radius: 4px;
  transition: background-color 0.3s ease;
}

.table-container::-webkit-scrollbar-thumb:hover {
  background-color: var(--ark-color-black);
}

.table-container:not(:hover)::-webkit-scrollbar-thumb {
  background-color: rgba(0, 0, 0, 0.05);
}

.connections-table {
  width: 100%;
  border-collapse: collapse;
}

.connections-table th {
  background-color: var(--ark-color-light-grey);
  padding: 12px;
  text-align: left;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--ark-color-black);
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.connections-table td {
  padding: 12px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
  color: var(--ark-color-black);
}

.connections-table tbody tr:last-child td {
  border-bottom: none;
}

.connections-table tbody tr.active-row {
  background-color: var(--ark-color-green-shadow);
}

.connection-name {
  display: flex;
  align-items: center;
  gap: 8px;
}

.capitalize {
  text-transform: capitalize;
}

.status-badge {
  display: inline-flex;
  padding: 4px 8px;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
}

.status-badge.active {
  background-color: var(--ark-color-green-shadow);
  color: var(--ark-color-green);
}

.status-badge.inactive {
  background-color: var(--ark-color-black-shadow);
  color: var(--ark-color-black);
}

.signal-container {
  width: 100px;
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 4px;
}

.signal-bar {
  height: 100%;
  border-radius: 4px;
}

.signal-bar.signal-strong {
  background-color: var(--ark-color-green);
}

.signal-bar.signal-medium {
  background-color: var(--ark-color-orange);
}

.signal-bar.signal-weak {
  background-color: var(--ark-color-red);
}

.signal-bar.signal-none {
  background-color: var(--ark-color-black-shadow);
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.icon-button {
  width: 32px;
  height: 32px;
  background: none;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}

.icon-button.configure:hover {
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
}

.icon-button.connect:hover {
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
}

.icon-button.disconnect:hover {
  background-color: var(--ark-color-red);
  color: var(--ark-color-white);
}

.icon-button.delete:hover {
  background-color: var(--ark-color-red);
  color: var(--ark-color-white);
}

.wifi-networks-container, .wifi-scan-container {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.wifi-scan-container {
  margin-bottom: 16px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
  padding: 12px;
  background-color: var(--ark-color-light-grey)
}

.wifi-scan-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.wifi-scan-header h3 {
  margin: 0;
  font-size: 1rem;
  color: var(--ark-color-black);
}

.wifi-scan-button {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  font-size: 0.8rem;
  cursor: pointer;
}

.wifi-networks-list {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 250px;
  overflow-y: auto;
  padding: 4px;
}

.wifi-networks-list::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

.wifi-networks-list::-webkit-scrollbar-thumb {
  background-color: var(--ark-color-black-shadow);
  border-radius: 3px;
}

.scanning-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(255, 255, 255, 0.9);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 5;
}

.empty-networks {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px 0;
  color: var(--ark-color-black);
  opacity: 0.6;
}

.empty-networks i {
  font-size: 2rem;
  margin-bottom: 8px;
}

.wifi-network-item {
  display: flex;
  align-items: center;
  padding: 12px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 8px;
  transition: all 0.2s;
}

.wifi-network-item:hover {
  box-shadow: 0 2px 6px var(--ark-color-black-shadow);
}

.wifi-network-item.connected {
  border-color: var(--ark-color-green);
  background-color: var(--ark-color-green-shadow);
}

.form-wifi-item {
  padding: 8px;
  cursor: pointer;
}

.form-wifi-item.selected {
  border-color: var(--ark-color-green);
  background-color: var(--ark-color-green-shadow);
}

.wifi-info {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.wifi-info i {
  font-size: 1.2rem;
}

.wifi-info i.signal-strong {
  color: var(--ark-color-green);
}

.wifi-info i.signal-medium {
  color: var(--ark-color-orange);
}

.wifi-info i.signal-weak {
  color: var(--ark-color-red);
}

.wifi-details {
  display: flex;
  flex-direction: column;
}

.wifi-name {
  font-weight: 500;
}

.security-badge {
  display: inline-flex;
  padding: 2px 6px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 4px;
  font-size: 0.7rem;
  color: var(--ark-color-black);
  margin-top: 4px;
  width: fit-content;
}

.wifi-signal {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  width: 80px;
}

.signal-value {
  font-size: 0.8rem;
  color: var(--ark-color-black);
}

/* Data Usage */
.usage-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
  overflow-x: hidden;  /* Prevent horizontal scrolling */
  overflow-y: auto;    /* Enable vertical scrolling */
  flex: 1;             /* Take up available space */
  padding: 4px 0;      /* Add vertical padding only */
  max-height: 100%;    /* Allow container to fill available space */
}

/* Rate-related styles */
.rate-bar-container {
  position: relative;
  height: 14px;
  background-color: var(--ark-color-light-grey);
  border-radius: 7px;
  overflow: hidden;
}

.rate-bar-fill {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  transition: width 0.5s ease-out;
  border-radius: 7px;
}

.rate-bar-fill.download {
  background-color: var(--ark-color-green);
}

.rate-bar-fill.upload {
  background-color: var(--ark-color-blue);
}

.download-value {
  color: var(--ark-color-green);
  font-weight: 500;
}

.upload-value {
  color: var(--ark-color-blue);
  font-weight: 500;
}

/* Responsive design for mobile */
@media (max-width: 576px) {
  .rate-display {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }

  .rate-label {
    width: auto;
    text-align: left;
  }

  .rate-bar-container {
    width: 100%;
  }
}

.statistics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
  margin-top: 10px;
  width: 100%;
  box-sizing: border-box;
}

.packet-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
  margin-top: 10px;
  width: 100%;
  box-sizing: border-box;
}

.stat-item {
  background-color: var(--ark-color-light-grey);
  border-radius: 4px;
  padding: 10px;
  display: flex;
  flex-direction: column;
}

.stat-label {
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
  margin-bottom: 4px;
}

.stat-value {
  font-weight: 500;
  font-size: 0.9rem;
}

.usage-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
  margin: 0 auto;
  max-width: 900px; /* Limit maximum width for better readability */
  flex: 1; /* Take up remaining space */
  height: auto; /* Let content determine height */
}

.usage-item {
  padding: 16px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 8px;
  margin-bottom: 12px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.usage-item:hover {
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
}

.usage-item.expanded {
  background-color: var(--ark-color-light-grey);
}

.usage-details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
  margin: 16px 0;
  background-color: var(--ark-color-light-grey);
  padding: 12px;
  border-radius: 4px;
}

.usage-detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.8rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.detail-value {
  font-weight: 500;
}

.usage-statistics {
  margin-top: 18px;
  padding-top: 14px;
  border-top: 1px dashed var(--ark-color-black-shadow);
}

.usage-stat-header {
  font-weight: 500;
  margin-bottom: 10px;
  font-size: 0.9rem;
  color: var(--ark-color-black);
}

.usage-item-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.usage-info {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.usage-name {
  font-weight: 600;
}

.usage-interface {
  color: var(--ark-color-black);
  opacity: 0.7;
  font-size: 0.9rem;
}

.interface-type {
  background-color: var(--ark-color-light-grey);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.8rem;
}

.usage-rates {
  display: flex;
  align-items: center;
  gap: 4px;
  font-family: monospace;
}

.rate-separator {
  margin: 0 2px;
  opacity: 0.5;
}

.rate-unit {
  margin-left: 2px;
  opacity: 0.7;
  font-size: 0.9rem;
  margin-right: 8px;
}

.usage-bars-compact {
  margin-bottom: 4px;
}

.usage-bars-compact .rate-bar-container {
  height: 4px;
  margin-bottom: 2px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 2px;
  overflow: hidden;
}

/* Expanded details section */
.usage-details-expanded {
  padding-top: 12px;
  margin-top: 12px;
  border-top: 1px dashed var(--ark-color-black-shadow);
  animation: fadeIn 0.3s ease;
  width: 100%;
  overflow-x: hidden;
  box-sizing: border-box;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Empty States */
.empty-state {
  padding: 32px;
  display: flex;
  justify-content: center;
  align-items: center;
}

.empty-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  color: var(--ark-color-black);
}

.empty-message i {
  font-size: 2rem;
  margin-bottom: 12px;
  opacity: 0.5;
}

.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.dialog-container {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.dialog-title {
  margin: 0;
  font-size: 1.2rem;
  font-weight: 600;
  color: var(--ark-color-black-bold);
}

.close-button {
  background: none;
  border: none;
  font-size: 1.2rem;
  color: var(--ark-color-black);
  cursor: pointer;
}

.dialog-content {
  padding: 16px;
}

/* Connection Type Selector */
.connection-type-selector {
  padding: 16px;
}

.connection-type-title {
  text-align: center;
  font-size: 1.1rem;
  font-weight: 500;
  margin-bottom: 16px;
}

.connection-type-options {
  display: flex;
  justify-content: space-around;
  gap: 16px;
}

.connection-type-button {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 16px;
  background-color: var(--ark-color-light-grey);
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
}

.connection-type-button:hover {
  background-color: var(--ark-color-green-shadow);
  border-color: var(--ark-color-green);
}

.connection-type-button i {
  font-size: 1.5rem;
  color: var(--ark-color-black);
}

/* Forms */
.connection-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-weight: 500;
  color: var(--ark-color-black-bold);
}

.form-group input, .form-group select {
  padding: 8px;
  border: 1px solid var(--ark-color-black-shadow);
  border-radius: 4px;
}

.radio-group {
  display: flex;
  gap: 16px;
}

.radio-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.password-input {
  position: relative;
}

.password-toggle {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--ark-color-black);
  cursor: pointer;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 48px;
  height: 24px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: var(--ark-color-black-shadow);
  transition: .4s;
  border-radius: 24px;
}

.toggle-slider:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  left: 4px;
  bottom: 4px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

input:checked + .toggle-slider {
  background-color: var(--ark-color-green);
}

input:checked + .toggle-slider:before {
  transform: translateX(24px);
}

.manual-ip-section {
  padding: 12px;
  background-color: var(--ark-color-light-grey);
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.form-buttons {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.cancel-button {
  padding: 8px 16px;
  background-color: var(--ark-color-black-shadow);
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.submit-button {
  padding: 8px 16px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.submit-button:hover {
  background-color: var(--ark-color-green-hover);
}

.info-label {
  font-size: 0.85rem;
  color: var(--ark-color-black);
  opacity: 0.7;
}

.info-value {
  font-size: 1rem;
  color: var(--ark-color-black-bold);
}

.signal-container {
  width: 100%;
  height: 8px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 4px;
}

.signal-bar {
  height: 100%;
  background-color: var(--ark-color-blue);
  border-radius: 4px;
}

/* Status badge colors */
.status-badge {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.8rem;
  color: var(--ark-color-white);
  text-transform: uppercase;
  font-weight: 500;
}

.status-badge.connected {
  background-color: var(--ark-color-green);
}

.status-badge.registered {
  background-color: var(--ark-color-blue);
}

.status-badge.searching {
  background-color: var(--ark-color-orange);
}

.status-badge.disabled, 
.status-badge.not_ready {
  background-color: var(--ark-color-red);
}

.status-badge.active {
  color: var(--ark-color-white);
  background-color: var(--ark-color-green);
}

.status-badge.inactive {
  color: var(--ark-color-white);
  background-color: var(--ark-color-black-shadow);
}

.text-success {
  color: var(--ark-color-green);
}

.connect-button {
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  padding: 8px 16px;
  cursor: pointer;
  transition: background-color 0.2s;
  align-self: flex-start;
}

.connect-button:hover {
  background-color: var(--ark-color-green-hover);
}

.connect-button:disabled {
  background-color: var(--ark-color-black-shadow);
  cursor: not-allowed;
}

.disconnect-button {
  background-color: var(--ark-color-red);
  color: var(--ark-color-white);
  border: none;
  border-radius: 4px;
  padding: 8px 16px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.disconnect-button:hover {
  background-color: var(--ark-color-red-hover);
}

.spinner {
  border: 4px solid var(--ark-color-black-shadow);
  border-top: 4px solid var(--ark-color-blue);
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

.error-message, .error-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 40px 0;
  color: var(--ark-color-red);
}

.error-message i, .error-container i {
  font-size: 2rem;
  margin-bottom: 16px;
}

.error-container p {
  margin-bottom: 16px;
  text-align: center;
  max-width: 80%;
}

/* Smaller, less intrusive error message */
.error-message-small {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 8px 16px;
  margin-bottom: 10px;
  background-color: rgba(244, 67, 54, 0.1);
  border-radius: 4px;
  color: var(--ark-color-red);
}

.error-message-small i {
  font-size: 1rem;
  margin-right: 8px;
}

.error-message-small p {
  margin: 0;
  font-size: 0.9rem;
}

.text-warning {
  color: var(--ark-color-orange);
}

.text-error {
  color: var(--ark-color-red);
}

/* Responsive Adjustments */
@media (max-width: 768px) {
  .tabs-container {
    flex-wrap: wrap;
  }
  
  .tab-button {
    min-width: 48%;
  }
  
  .connection-type-options {
    flex-direction: column;
  }

}

/* New LTE Layout Styles */
.lte-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
  width: 100%;
}

.lte-status-header-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  padding: 16px;
}

.status-header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
}

.status-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.roaming-badge {
  padding: 4px 8px;
  background-color: var(--ark-color-blue);
  color: var(--ark-color-white);
  font-size: 0.8rem;
  border-radius: 12px;
  font-weight: 500;
}

.signal-info {
  display: flex;
  flex-direction: column;
  width: 140px;
}

.signal-label {
  display: flex;
  justify-content: space-between;
  font-size: 0.8rem;
  margin-bottom: 4px;
}

.signal-container.wide {
  width: 140px;
}

.apn-info {
  display: flex;
  flex-direction: column;
}

/* Top two-column grid for Carrier and Hardware info */
.lte-info-top-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.lte-info-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  padding: 16px;
}

/* Full-width connection card */
.lte-connection-card {
  width: 100%;
  box-sizing: border-box;
}

.card-title {
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 12px 0;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
}

.carrier-title {
  color: var(--ark-color-blue);
}

.hardware-title {
  color: var(--ark-color-black);
}

.connection-title {
  color: var(--ark-color-green);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.connection-info-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-secondary {
  color: var(--ark-color-black);
  opacity: 0.6;
  font-size: 0.8rem;
  margin-left: 4px;
}

.monospace {
  font-family: monospace;
  font-size: 0.9rem;
}

.capitalize {
  text-transform: capitalize;
}

.not-connected {
  height: 100px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--ark-color-black);
  opacity: 0.6;
  font-style: italic;
}

/* DNS Servers Section */
.dns-section {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid var(--ark-color-black-shadow);
}

.text-success {
  color: var(--ark-color-green);
}

.text-error {
  color: var(--ark-color-red);
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .status-header-content {
    flex-direction: column;
    align-items: flex-start;
  }

  .lte-info-top-grid {
    grid-template-columns: 1fr;
  }

  .info-grid, .connection-info-grid {
    grid-template-columns: 1fr;
  }
}

/* Status tags for interface state and IP method */
.status-tag {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 500;
  margin-left: 6px;
  text-transform: uppercase;
}

.status-up {
  background-color: rgba(0, 187, 49, 0.15);
  color: var(--ark-color-green);
}

.status-down {
  background-color: rgba(244, 67, 54, 0.15);
  color: var(--ark-color-red);
}

.status-method {
  background-color: rgba(52, 152, 219, 0.15);
  color: var(--ark-color-blue);
  text-transform: lowercase;
}

.dns-value {
  display: flex;
  align-items: center;
}

.readonly-input {
  background-color: var(--ark-color-light-grey);
  cursor: not-allowed;
  opacity: 0.8;
}

.duplicate-warning {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background-color: rgba(255, 193, 7, 0.1);
  border-left: 3px solid var(--ark-color-orange);
  border-radius: 4px;
  color: var(--ark-color-orange);
  font-size: 0.9rem;
  margin: 8px 0;
}

.duplicate-warning i {
  font-size: 1rem;
}

.disabled-button {
  background-color: var(--ark-color-black-shadow) !important;
  cursor: not-allowed !important;
  opacity: 0.6;
}

.icon-container {
  display: inline-block;
  width: 18px; /* Fixed width for all icons */
  text-align: center; /* Center the icon within the container */
  margin-right: 8px; /* Consistent spacing between icon and text */
}

.connection-type-button.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.connection-type-note {
  display: block;
  font-size: 0.7rem;
  color: #d32f2f;
  margin-top: 5px;
}

.loading-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 0;
  text-align: center;
}

.loading-container p {
  margin-top: 16px;
  color: var(--ark-color-black);
  font-size: 1rem;
}

</style>
