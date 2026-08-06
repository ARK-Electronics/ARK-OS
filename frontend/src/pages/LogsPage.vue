<template>
  <div class="page-container">
    <h1 class="page-title">Logs</h1>

    <div v-if="loading" class="loading-container">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Loading logs...</p>
    </div>

    <div v-else-if="error" class="error-container">
      <i class="fas fa-exclamation-triangle"></i>
      <h2>Unable to Load Logs</h2>
      <p>{{ error }}</p>
      <button @click="retry" class="retry-button">
        <i class="fas fa-refresh"></i> Retry
      </button>
    </div>

    <div v-else class="logs-content">
      <div class="section-container">
        <div class="status-bar">
          <span class="status-item">
            <span class="dot" :class="status.connected ? 'dot-ok' : 'dot-bad'"></span>
            {{ status.connected ? 'Vehicle connected' : 'Waiting for the vehicle' }}
          </span>
          <span class="status-item" v-if="status.connected">
            <span class="dot" :class="status.ftp_available ? 'dot-ok' : 'dot-bad'"></span>
            {{ status.ftp_available ? `MAVLink FTP: ${status.log_root}` : 'MAVLink FTP unavailable' }}
          </span>
          <span class="status-item" v-if="status.logging">
            <span class="dot dot-ok"></span> Logger running
          </span>
          <span class="status-item warning" v-if="!streamConnected">
            <i class="fas fa-exclamation-triangle"></i> Live updates disconnected — reconnecting
          </span>
          <span class="status-item warning" v-if="status.armed">
            <i class="fas fa-exclamation-triangle"></i> Armed — transfers are paused
          </span>
          <span class="status-item counts">
            {{ logs.length }} logs · {{ downloadedCount }} downloaded · {{ uploadedCount }} uploaded
          </span>
        </div>
      </div>

      <div class="section-container">
        <div class="section-header">
          <h2 class="section-title">
            {{ selected.length ? `${selected.length} selected` : 'Select logs to download or upload' }}
          </h2>
          <div class="actions-bar">
            <button class="action-button primary" :disabled="!selected.length || busy"
              @click="downloadSelected">
              <i class="fas fa-download"></i> Download &amp; Upload
            </button>
            <button class="action-button" :disabled="!selected.length || busy" @click="downloadOnly">
              <i class="fas fa-hdd"></i> Download Only
            </button>
            <button class="action-button" :disabled="!uploadableSelected.length || busy"
              @click="uploadSelected">
              <i class="fas fa-cloud-upload-alt"></i> Upload
            </button>
            <button class="action-button danger" :disabled="!cancellableSelected.length || busy"
              @click="cancelSelected">
              <i class="fas fa-times"></i> Cancel
            </button>
            <button class="action-button" :disabled="busy" @click="refreshVehicle"
              title="List the vehicle's logs again">
              <i class="fas fa-sync-alt"></i> Refresh
            </button>
          </div>
        </div>

        <p v-if="message" class="message">{{ message }}</p>

        <div class="table-container">
          <table class="logs-table">
            <thead>
              <tr>
                <th class="checkbox-cell">
                  <input type="checkbox" :checked="allSelected" :indeterminate.prop="someSelected"
                    :disabled="!logs.length" @change="toggleAll" title="Select all">
                </th>
                <th>Date (local)</th>
                <th>Name</th>
                <th>Size</th>
                <th>On Vehicle</th>
                <th>Downloaded</th>
                <th v-for="target in targets" :key="target.name">{{ targetLabel(target.name) }}</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="log in logs" :key="log.id" :class="{ 'active-row': log.id === status.downloading_id }">
                <td class="checkbox-cell">
                  <input type="checkbox" :value="log.id" v-model="selected">
                </td>
                <td class="nowrap">{{ formatDate(log.date) }}</td>
                <td class="name-cell" :title="log.path">{{ log.name }}</td>
                <td class="nowrap">{{ formatSize(log.size_bytes) }}</td>
                <td>
                  <i v-if="log.present" class="fas fa-check state-ok" title="Still on the vehicle"></i>
                  <i v-else class="fas fa-minus state-muted" title="No longer on the vehicle"></i>
                </td>
                <td>
                  <div v-if="log.id === status.downloading_id" class="progress">
                    <div class="progress-fill" :style="{ width: downloadPercent + '%' }"></div>
                    <span class="progress-text">{{ downloadPercent }}%</span>
                  </div>
                  <i v-else-if="log.downloaded" class="fas fa-check state-ok" title="Downloaded"></i>
                  <i v-else-if="log.download_requested" class="fas fa-clock state-pending" title="Queued"></i>
                  <i v-else class="fas fa-minus state-muted"></i>
                </td>
                <td v-for="target in targets" :key="target.name">
                  <a v-if="uploadOf(log, target.name).uploaded && uploadOf(log, target.name).location"
                    :href="plotUrl(target, uploadOf(log, target.name).location)" target="_blank"
                    rel="noopener noreferrer" class="plot-link" title="Open in Flight Review">
                    <i class="fas fa-external-link-alt"></i> View
                  </a>
                  <i v-else-if="uploadOf(log, target.name).uploaded" class="fas fa-check state-ok"></i>
                  <i v-else-if="log.id === status.uploading_id && status.uploading_target === target.name"
                    class="fas fa-spinner fa-spin state-pending" title="Uploading"></i>
                  <i v-else-if="uploadOf(log, target.name).rejected" class="fas fa-ban state-bad"
                    :title="uploadOf(log, target.name).message"></i>
                  <i v-else-if="uploadOf(log, target.name).requested" class="fas fa-clock state-pending"
                    title="Queued"></i>
                  <i v-else class="fas fa-minus state-muted"></i>
                </td>
                <td>
                  <div class="actions">
                    <button v-if="log.downloaded" class="icon-button danger"
                      title="Delete the downloaded copy" @click="deleteFile(log)">
                      <i class="fas fa-trash"></i>
                    </button>
                    <span v-if="log.last_error" class="row-error" :title="log.last_error">
                      <i class="fas fa-exclamation-triangle"></i>
                    </span>
                  </div>
                </td>
              </tr>
              <tr v-if="logs.length === 0">
                <td :colspan="7 + targets.length" class="empty-state">
                  <div class="empty-message">
                    <i class="fas fa-book"></i>
                    <p>{{ status.connected ? 'No logs on the vehicle yet' : 'Waiting for the vehicle' }}</p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import LogsService from '@/services/LogsService';

// logloader only ever reports the path Flight Review redirected to, because
// that is all the server sends back. The local instance is reachable through
// nginx on whatever host the browser is on -- not the 127.0.0.1 logloader
// uploaded to -- so it gets the proxy prefix; a remote one gets its own origin.
const LOCAL_FLIGHT_REVIEW_PREFIX = '/flight-review';

export default {
  name: 'LogsPage',
  data() {
    return {
      logs: [],
      targets: [],
      status: {},
      selected: [],
      loading: true,
      error: null,
      busy: false,
      message: '',
      streamConnected: false,
      eventSource: null,
      messageTimer: null,
    };
  },
  computed: {
    downloadedCount() {
      return this.logs.filter((log) => log.downloaded).length;
    },
    uploadedCount() {
      return this.logs.filter((log) => this.targets.some((t) => this.uploadOf(log, t.name).uploaded)).length;
    },
    allSelected() {
      return this.logs.length > 0 && this.selected.length === this.logs.length;
    },
    someSelected() {
      return this.selected.length > 0 && this.selected.length < this.logs.length;
    },
    selectedLogs() {
      return this.logs.filter((log) => this.selected.includes(log.id));
    },
    // Uploading needs the file, so a log that is neither downloaded nor still on
    // the vehicle cannot be uploaded at all.
    uploadableSelected() {
      return this.selectedLogs.filter(
        (log) => (log.downloaded || log.present)
          && this.targets.some((t) => !this.uploadOf(log, t.name).uploaded)
      );
    },
    cancellableSelected() {
      return this.selectedLogs.filter(
        (log) => log.download_requested || this.targets.some((t) => this.uploadOf(log, t.name).requested)
      );
    },
    downloadPercent() {
      const total = this.status.download_total_bytes;
      if (!total) return 0;
      return Math.round((100 * this.status.downloaded_bytes) / total);
    },
  },
  mounted() {
    this.fetchLogs();
    this.connectStream();
    // Nothing polls the vehicle; ask for a fresh listing now that someone is
    // actually looking. Ignored until the vehicle is connected and disarmed.
    LogsService.refresh().catch(() => {});
  },
  beforeUnmount() {
    this.disconnectStream();
    clearTimeout(this.messageTimer);
  },
  methods: {
    async fetchLogs() {
      this.loading = true;
      try {
        const response = await LogsService.getLogs();
        this.applyPayload(response.data);
        this.loading = false;
        this.error = null;
      } catch (error) {
        this.loading = false;
        this.error = error.response?.data?.error
          || error.message
          || 'Failed to reach logloader. Is the service running?';
      }
    },

    applyPayload(payload) {
      this.logs = payload.logs || [];
      this.targets = payload.targets || [];
      this.status = payload.status || {};

      // Drop selections for logs that are gone, so an action cannot be sent for
      // an id the backend no longer knows.
      const known = new Set(this.logs.map((log) => log.id));
      this.selected = this.selected.filter((id) => known.has(id));
    },

    connectStream() {
      this.disconnectStream();

      const source = new EventSource(LogsService.eventsUrl());
      this.eventSource = source;

      source.onopen = () => { this.streamConnected = true; };

      // The full list only arrives when it changed. Transfer progress ticks
      // several times a second and comes through as `status` alone.
      source.addEventListener('logs', (event) => {
        const payload = this.parseEvent(event);
        if (!payload) return;
        this.applyPayload(payload);
        this.loading = false;
        this.error = null;
      });

      source.addEventListener('status', (event) => {
        const status = this.parseEvent(event);
        if (status) this.status = status;
      });

      source.onerror = () => {
        // EventSource reconnects on its own; say so rather than showing a table
        // that has quietly stopped changing.
        this.streamConnected = false;
      };
    },

    parseEvent(event) {
      try {
        return JSON.parse(event.data);
      } catch {
        return null;
      }
    },

    disconnectStream() {
      if (this.eventSource) {
        this.eventSource.close();
        this.eventSource = null;
      }
      this.streamConnected = false;
    },

    async run(action, describe) {
      this.busy = true;
      this.setMessage('');
      try {
        const response = await action();
        this.setMessage(describe(response.data));
      } catch (error) {
        this.setMessage(error.response?.data?.error || error.message || 'Request failed');
      } finally {
        this.busy = false;
      }
    },

    setMessage(text) {
      clearTimeout(this.messageTimer);
      this.message = text;
      if (text) {
        this.messageTimer = setTimeout(() => { this.message = ''; }, 8000);
      }
    },

    downloadSelected() {
      this.run(
        () => LogsService.requestDownload(this.selected, true),
        (data) => `Queued ${data.queued} log(s) for download and upload`
      );
    },

    downloadOnly() {
      this.run(
        () => LogsService.requestDownload(this.selected, false),
        (data) => `Queued ${data.queued} log(s) for download`
      );
    },

    uploadSelected() {
      const logs = this.uploadableSelected;
      const ids = logs.map((log) => log.id);
      // Only the targets that are actually missing one of these logs, so a
      // request cannot re-queue a target that already has them all.
      const targets = this.targets
        .filter((t) => logs.some((log) => !this.uploadOf(log, t.name).uploaded))
        .map((t) => t.name);
      this.run(
        () => LogsService.requestUpload(ids, targets),
        (data) => `Queued ${data.queued} log(s) for upload`
      );
    },

    cancelSelected() {
      const ids = this.cancellableSelected.map((log) => log.id);
      this.run(
        () => LogsService.cancelRequests(ids),
        (data) => `Cancelled ${data.cancelled} pending request(s)`
      );
    },

    refreshVehicle() {
      // Fire-and-forget: the new listing arrives over the event stream.
      LogsService.refresh().catch(() => {});
      this.setMessage(this.status.connected
        ? 'Checking the vehicle for logs…'
        : 'Refresh queued; it runs when the vehicle reconnects');
    },

    deleteFile(log) {
      if (!window.confirm(`Delete the downloaded copy of ${log.name}? `
        + 'It can be fetched again while it is still on the vehicle.')) {
        return;
      }
      this.run(
        () => LogsService.deleteLocalFile(log.id),
        () => `Deleted the local copy of ${log.name}`
      );
    },

    toggleAll(event) {
      this.selected = event.target.checked ? this.logs.map((log) => log.id) : [];
    },

    uploadOf(log, target) {
      return (log.uploads && log.uploads[target]) || {};
    },

    targetLabel(target) {
      return target === 'local' ? 'Flight Review' : 'Remote';
    },

    plotUrl(target, location) {
      if (target.name === 'local') return `${LOCAL_FLIGHT_REVIEW_PREFIX}${location}`;
      return target.url ? `${target.url.replace(/\/$/, '')}${location}` : location;
    },

    formatSize(bytes) {
      if (!bytes) return '-';
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    },

    formatDate(date) {
      if (!date) return '-';
      const parsed = new Date(date);
      if (Number.isNaN(parsed.getTime())) return date;
      const p = (n) => String(n).padStart(2, '0');
      return `${parsed.getFullYear()}-${p(parsed.getMonth() + 1)}-${p(parsed.getDate())} `
        + `${p(parsed.getHours())}:${p(parsed.getMinutes())}`;
    },

    retry() {
      this.loading = true;
      this.error = null;
      this.fetchLogs();
      this.connectStream();
    },
  },
};
</script>

<style scoped>
.page-container {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
  padding-right: 40px;
  gap: 24px;
  box-sizing: border-box;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
  text-align: center;
}

.logs-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section-container {
  width: 100%;
  box-shadow: 0 2px 8px var(--ark-color-black-shadow);
  background-color: var(--ark-color-white);
  border-radius: 8px;
  padding: 20px;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
  gap: 16px;
  flex-wrap: wrap;
}

.section-title {
  font-size: 1.3rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
}

.status-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  align-items: center;
  color: var(--ark-color-black);
  font-size: 0.9rem;
}

.status-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-item.warning {
  color: var(--ark-color-orange);
  font-weight: 600;
}

.status-item.counts {
  margin-left: auto;
  color: var(--ark-color-grey);
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}

.dot-ok {
  background-color: var(--ark-color-green);
}

.dot-bad {
  background-color: var(--ark-color-red);
}

.actions-bar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.action-button {
  padding: 8px 14px;
  border: 1px solid var(--ark-color-black-shadow);
  background-color: var(--ark-color-white);
  color: var(--ark-color-black);
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.2s, opacity 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.action-button:hover:not(:disabled) {
  background-color: var(--ark-color-light-grey);
}

.action-button.primary {
  background-color: var(--ark-color-green);
  border-color: var(--ark-color-green);
  color: var(--ark-color-white);
}

.action-button.primary:hover:not(:disabled) {
  background-color: var(--ark-color-green-hover);
}

.action-button.danger {
  color: var(--ark-color-red);
}

.action-button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.message {
  margin: 0 0 16px 0;
  color: var(--ark-color-grey);
  font-size: 0.9rem;
}

.table-container {
  width: 100%;
  overflow-x: auto;
  border-radius: 4px;
  border: 1px solid var(--ark-color-black-shadow);
}

.logs-table {
  width: 100%;
  border-collapse: collapse;
}

.logs-table th {
  background-color: var(--ark-color-light-grey);
  padding: 12px;
  text-align: left;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--ark-color-black);
  border-bottom: 1px solid var(--ark-color-black-shadow);
  white-space: nowrap;
}

.logs-table td {
  padding: 12px;
  border-bottom: 1px solid var(--ark-color-black-shadow);
  color: var(--ark-color-black);
}

.logs-table tbody tr:last-child td {
  border-bottom: none;
}

.logs-table tbody tr.active-row {
  background-color: var(--ark-color-green-shadow);
}

.checkbox-cell {
  width: 40px;
}

.nowrap {
  white-space: nowrap;
}

.name-cell {
  font-family: monospace;
  font-size: 0.85rem;
}

.state-ok {
  color: var(--ark-color-green);
}

.state-bad {
  color: var(--ark-color-red);
}

.state-pending {
  color: var(--ark-color-blue);
}

.state-muted {
  color: var(--ark-color-grey);
}

.progress {
  position: relative;
  width: 90px;
  height: 16px;
  background-color: var(--ark-color-light-grey);
  border-radius: 8px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background-color: var(--ark-color-green);
  transition: width 0.3s;
}

.progress-text {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.7rem;
  color: var(--ark-color-black-bold);
}

.plot-link {
  color: var(--ark-color-blue);
  text-decoration: none;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
}

.plot-link:hover {
  text-decoration: underline;
}

.actions {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 24px;
}

.icon-button {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px 6px;
  border-radius: 4px;
  color: var(--ark-color-grey);
}

.icon-button.danger:hover {
  color: var(--ark-color-red);
  background-color: var(--ark-color-light-grey);
}

.row-error {
  color: var(--ark-color-orange);
}

.empty-state {
  text-align: center;
  padding: 40px;
}

.empty-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  color: var(--ark-color-grey);
}

.empty-message i {
  font-size: 2rem;
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
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
}
</style>
