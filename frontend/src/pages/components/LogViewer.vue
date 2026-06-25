<template>
  <div class="log-viewer-backdrop" @click.self="closeViewer">
    <div class="log-viewer-container">
      <div class="log-header">
        <h2>{{ serviceName }}</h2>
        <span class="live-status" :class="{ live: connected }">
          <span class="dot"></span>{{ connected ? 'live' : 'reconnecting…' }}
        </span>
      </div>

      <div class="log-body" ref="logBody" @scroll="onScroll">
        <div v-if="errorMessage" class="log-error">{{ errorMessage }}</div>
        <div v-else-if="lines.length === 0" class="log-empty">Waiting for log output…</div>
        <div v-for="line in lines" :key="line.id" class="log-row">
          <span class="log-ts" :title="formatFull(line.ts)">{{ formatTime(line.ts) }}</span>
          <span class="log-msg" :class="priorityClass(line.priority)">{{ line.message }}</span>
        </div>
      </div>

      <button v-if="!stickToBottom" class="jump-button" @click="jumpToBottom">
        Jump to latest ↓
      </button>

      <div class="actions">
        <button @click="closeViewer" class="close-button">Close</button>
      </div>
    </div>
  </div>
</template>

<script>
// Keep memory bounded on long-lived streams; the newest lines are what matters.
const MAX_LINES = 2000;
// Treat "within this many px of the bottom" as actively following the tail.
const STICK_THRESHOLD = 24;

export default {
  props: ['serviceName'],
  data() {
    return {
      lines: [],
      logSource: null,
      connected: false,
      errorMessage: '',
      stickToBottom: true,
      nextId: 0,
    };
  },
  mounted() {
    this.connectStream();
  },
  beforeUnmount() {
    this.disconnectStream();
  },
  methods: {
    connectStream() {
      this.disconnectStream();

      const url = `/api/service/logs/stream?serviceName=${encodeURIComponent(this.serviceName)}`;
      const source = new EventSource(url);
      this.logSource = source;

      source.onopen = () => {
        // The backend re-seeds the last 200 lines on every (re)connect, so clear
        // first to avoid duplicating history after an automatic reconnect.
        this.lines = [];
        this.connected = true;
        this.errorMessage = '';
        this.stickToBottom = true;
      };

      source.addEventListener('log_line', (event) => {
        let entry;
        try {
          entry = JSON.parse(event.data);
        } catch {
          return;
        }
        this.appendLine(entry);
      });

      source.addEventListener('log_error', (event) => {
        try {
          this.errorMessage = JSON.parse(event.data).message || 'Log stream error';
        } catch {
          this.errorMessage = 'Log stream error';
        }
        // The backend closes after an error event; stop EventSource from
        // reconnecting in a loop against an unmanaged service.
        this.disconnectStream();
        this.connected = false;
      });

      source.onerror = () => {
        // Connection-level error only; EventSource reconnects on its own.
        this.connected = false;
      };
    },

    appendLine(entry) {
      this.lines.push({ id: this.nextId++, ...entry });
      if (this.lines.length > MAX_LINES) {
        this.lines.splice(0, this.lines.length - MAX_LINES);
      }
      if (this.stickToBottom) {
        this.$nextTick(this.scrollToBottom);
      }
    },

    onScroll() {
      const el = this.$refs.logBody;
      if (!el) return;
      this.stickToBottom = el.scrollHeight - el.scrollTop - el.clientHeight < STICK_THRESHOLD;
    },

    scrollToBottom() {
      const el = this.$refs.logBody;
      if (el) el.scrollTop = el.scrollHeight;
    },

    jumpToBottom() {
      this.stickToBottom = true;
      this.$nextTick(this.scrollToBottom);
    },

    formatTime(ts) {
      if (!ts) return '';
      const d = new Date(ts);
      const p = (n, w = 2) => String(n).padStart(w, '0');
      return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
    },

    formatFull(ts) {
      return ts ? new Date(ts).toLocaleString() : '';
    },

    priorityClass(priority) {
      if (priority <= 3) return 'sev-error';
      if (priority === 4) return 'sev-warn';
      if (priority >= 7) return 'sev-debug';
      return '';
    },

    disconnectStream() {
      if (this.logSource) {
        this.logSource.close();
        this.logSource = null;
      }
    },

    closeViewer() {
      this.disconnectStream();
      this.$emit('close-viewer');
    },
  },
};
</script>

<style scoped>
.log-viewer-backdrop {
  position: fixed;
  inset: 0;
  background-color: var(--ark-color-black);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.log-viewer-container {
  position: relative;
  background-color: var(--ark-color-white);
  padding: 20px;
  border-radius: 12px;
  width: 80vw;
  max-width: 1100px;
  height: 80vh;
  max-height: 85vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0px 0px 20px var(--ark-color-black-shadow);
}

.log-header {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  margin-bottom: 14px;
}

.log-header h2 {
  margin: 0;
  color: var(--ark-color-black);
}

.live-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--ark-color-orange);
}

.live-status.live {
  color: var(--ark-color-green);
}

.live-status .dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background-color: currentColor;
}

.live-status.live .dot {
  animation: pulse 1.6s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.log-body {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  background-color: #1e1e1e;
  border-radius: 6px;
  padding: 12px 14px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
  color: #d4d4d4;
  text-align: left;
}

.log-row {
  display: flex;
  gap: 12px;
  align-items: baseline;
}

.log-ts {
  flex: 0 0 auto;
  color: #6a8caf;
  user-select: none;
  -webkit-user-select: none;
}

.log-msg {
  flex: 1 1 auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.sev-error { color: #f48771; }
.sev-warn  { color: #e2c08d; }
.sev-debug { color: #808080; }

.log-empty,
.log-error {
  color: #9aa0a6;
  font-style: italic;
  padding: 8px 0;
}

.log-error {
  color: #f48771;
  font-style: normal;
}

.jump-button {
  position: absolute;
  right: 36px;
  bottom: 84px;
  padding: 6px 12px;
  border: none;
  border-radius: 16px;
  background-color: var(--ark-color-green);
  color: var(--ark-color-white);
  cursor: pointer;
  font-size: 13px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35);
}

.actions {
  display: flex;
  justify-content: center;
  margin-top: 16px;
}

.close-button {
  padding: 12px 20px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 16px;
  font-weight: 600;
  background-color: var(--ark-color-red);
  color: var(--ark-color-white);
  transition: background-color 0.3s ease;
}

.close-button:hover {
  background-color: var(--ark-color-red-hover);
}
</style>
