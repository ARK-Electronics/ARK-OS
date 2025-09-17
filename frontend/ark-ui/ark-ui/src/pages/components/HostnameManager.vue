<template>
  <div class="hostname-section">
    <div class="section-header">
      <h2 class="section-title">
        <i class="fas fa-server"></i>
        Hostname Management
      </h2>
    </div>

    <div class="hostname-card">
      <div class="current-hostname">
        <span class="label">Current Hostname:</span>
        <span class="value">{{ currentHostname || 'Unknown' }}</span>
      </div>

      <div class="hostname-form">
        <div class="input-group">
          <input
            v-model="newHostname"
            class="hostname-input"
            :class="{ invalid: newHostname && !isValidHostname }"
            placeholder="Enter new hostname"
            @keyup.enter="changeHostname"
            maxlength="63"
          />
          <button
            @click="changeHostname"
            class="change-button"
            :disabled="!canChangeHostname"
          >
            <i v-if="isChanging" class="fas fa-spinner fa-spin"></i>
            <i v-else class="fas fa-edit"></i>
            <span>{{ isChanging ? 'Changing...' : 'Change' }}</span>
          </button>
        </div>

        <small class="hint">
          Only alphanumeric characters and hyphens allowed (max 63 characters)
        </small>
      </div>

      <!-- Status Messages -->
      <transition name="fade">
        <div v-if="message" class="message" :class="messageClass">
          <i :class="messageIcon"></i>
          <span>{{ message }}</span>
        </div>
      </transition>
    </div>

    <!-- Confirmation Dialog -->
    <transition name="modal">
      <div v-if="showConfirm" class="modal-overlay" @click.self="cancelChange">
        <div class="modal-dialog">
          <div class="modal-header">
            <h3>Confirm Hostname Change</h3>
            <button @click="cancelChange" class="close-btn">
              <i class="fas fa-times"></i>
            </button>
          </div>

          <div class="modal-body">
            <div class="warning-icon">
              <i class="fas fa-exclamation-triangle"></i>
            </div>
            <p>
              Change hostname from <strong>{{ currentHostname }}</strong> to
              <strong>{{ newHostname }}</strong>?
            </p>
            <p class="warning-text">
              A system reboot will be required for this change to take effect.
            </p>
          </div>

          <div class="modal-footer">
            <button @click="cancelChange" class="btn-cancel">Cancel</button>
            <button @click="confirmChange" class="btn-confirm" :disabled="isChanging">
              <i v-if="isChanging" class="fas fa-spinner fa-spin"></i>
              <span>{{ isChanging ? 'Changing...' : 'Confirm' }}</span>
            </button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script>
import SystemService from '@/services/SystemService';

export default {
  name: 'HostnameManager',
  props: {
    currentHostname: {
      type: String,
      default: ''
    }
  },
  data() {
    return {
      newHostname: '',
      isChanging: false,
      showConfirm: false,
      message: '',
      messageType: null,
      messageTimeout: null
    };
  },
  computed: {
    isValidHostname() {
      if (!this.newHostname) return false;
      const hostnameRegex = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
      return hostnameRegex.test(this.newHostname);
    },

    canChangeHostname() {
      return this.isValidHostname &&
             !this.isChanging &&
             this.newHostname !== this.currentHostname;
    },

    messageClass() {
      return {
        'success': this.messageType === 'success',
        'error': this.messageType === 'error',
        'warning': this.messageType === 'warning'
      };
    },

    messageIcon() {
      switch(this.messageType) {
        case 'success': return 'fas fa-check-circle';
        case 'error': return 'fas fa-exclamation-circle';
        case 'warning': return 'fas fa-exclamation-triangle';
        default: return 'fas fa-info-circle';
      }
    }
  },

  methods: {
    changeHostname() {
      if (!this.canChangeHostname) return;
      this.showConfirm = true;
    },

    cancelChange() {
      this.showConfirm = false;
    },

    async confirmChange() {
      this.isChanging = true;
      this.clearMessage();

      try {
        const response = await SystemService.changeHostname(this.newHostname);

        if (response.data && response.data.success) {
          this.showMessage(response.data.message, 'success');
          this.newHostname = '';
          this.showConfirm = false;
          this.$emit('hostnameChanged', this.newHostname);
        } else {
          throw new Error(response.data?.message || 'Failed to change hostname');
        }
      } catch (error) {
        const errorMsg = error.response?.data?.message ||
                        error.message ||
                        'Failed to change hostname';
        this.showMessage(errorMsg, 'error');
      } finally {
        this.isChanging = false;
        this.showConfirm = false;
      }
    },

    showMessage(text, type) {
      this.message = text;
      this.messageType = type;

      // Clear existing timeout
      if (this.messageTimeout) {
        clearTimeout(this.messageTimeout);
      }

      // Auto-clear message after 5 seconds
      this.messageTimeout = setTimeout(() => {
        this.clearMessage();
      }, 5000);
    },

    clearMessage() {
      this.message = '';
      this.messageType = null;
      if (this.messageTimeout) {
        clearTimeout(this.messageTimeout);
        this.messageTimeout = null;
      }
    }
  },

  beforeUnmount() {
    this.clearMessage();
  }
}
</script>

<style scoped>
.hostname-section {
  width: 100%;
  margin-top: 20px;
}

.section-header {
  margin-bottom: 16px;
}

.section-title {
  font-size: 1.4rem;
  font-weight: 600;
  color: var(--ark-color-black);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}

.section-title i {
  font-size: 1.2rem;
  color: var(--ark-color-blue);
}

.hostname-card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.current-hostname {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 20px;
  padding: 12px;
  background: #f5f5f5;
  border-radius: 6px;
}

.current-hostname .label {
  font-weight: 500;
  color: #666;
}

.current-hostname .value {
  font-weight: 600;
  color: var(--ark-color-black);
  font-family: monospace;
  font-size: 1.1rem;
}

.hostname-form {
  margin-bottom: 16px;
}

.input-group {
  display: flex;
  gap: 12px;
  margin-bottom: 8px;
}

.hostname-input {
  flex: 1;
  padding: 10px 14px;
  border: 2px solid #e0e0e0;
  border-radius: 6px;
  font-size: 1rem;
  font-family: monospace;
  transition: border-color 0.2s;
}

.hostname-input:focus {
  outline: none;
  border-color: var(--ark-color-blue);
}

.hostname-input.invalid {
  border-color: #f44336;
}

.change-button {
  padding: 10px 20px;
  background: var(--ark-color-blue);
  color: white;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 120px;
  justify-content: center;
}

.change-button:hover:not(:disabled) {
  background: var(--ark-color-blue-hover);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
}

.change-button:disabled {
  background: #ccc;
  cursor: not-allowed;
  opacity: 0.6;
}

.hint {
  display: block;
  color: #666;
  font-size: 0.85rem;
  margin-top: 8px;
}

/* Messages */
.message {
  padding: 12px 16px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 16px;
}

.message.success {
  background: #e8f5e9;
  color: #2e7d32;
  border: 1px solid #a5d6a7;
}

.message.error {
  background: #ffebee;
  color: #c62828;
  border: 1px solid #ef9a9a;
}

.message.warning {
  background: #fff3e0;
  color: #e65100;
  border: 1px solid #ffcc80;
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-dialog {
  background: white;
  border-radius: 12px;
  width: 90%;
  max-width: 500px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid #e0e0e0;
}

.modal-header h3 {
  margin: 0;
  font-size: 1.3rem;
  color: var(--ark-color-black);
}

.close-btn {
  background: none;
  border: none;
  font-size: 1.2rem;
  color: #666;
  cursor: pointer;
  padding: 4px 8px;
  transition: color 0.2s;
}

.close-btn:hover {
  color: #333;
}

.modal-body {
  padding: 24px;
  text-align: center;
}

.warning-icon {
  font-size: 3rem;
  color: #ff9800;
  margin-bottom: 16px;
}

.modal-body p {
  margin: 12px 0;
  color: #333;
  line-height: 1.5;
}

.modal-body strong {
  color: var(--ark-color-black);
  font-family: monospace;
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 3px;
}

.warning-text {
  color: #666;
  font-size: 0.95rem;
  font-style: italic;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 16px 20px;
  border-top: 1px solid #e0e0e0;
}

.btn-cancel,
.btn-confirm {
  padding: 8px 20px;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 6px;
}

.btn-cancel {
  background: #f5f5f5;
  color: #666;
}

.btn-cancel:hover {
  background: #e0e0e0;
}

.btn-confirm {
  background: var(--ark-color-blue);
  color: white;
}

.btn-confirm:hover:not(:disabled) {
  background: var(--ark-color-blue-hover);
}

.btn-confirm:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-active .modal-dialog,
.modal-leave-active .modal-dialog {
  transition: transform 0.3s;
}

.modal-enter-from .modal-dialog {
  transform: scale(0.9);
}

.modal-leave-to .modal-dialog {
  transform: scale(0.9);
}

/* Responsive */
@media (max-width: 600px) {
  .input-group {
    flex-direction: column;
  }

  .change-button {
    width: 100%;
  }
}
</style>
