<template>
  <div class="system-card">
    <div class="card-header">
      <i :class="['fas', icon, 'icon-color']"></i>
      <span class="header-title">{{ title }}</span>
    </div>

    <div class="card-content">
      <!-- Loading State -->
      <div v-if="loading" class="loading-state">
        <i class="fas fa-spinner fa-spin"></i>
        <span>Loading...</span>
      </div>

      <!-- No Data State -->
      <div v-else-if="!data" class="no-data-state">
        <i class="fas fa-exclamation-circle"></i>
        <span>Data unavailable</span>
      </div>

      <!-- Data Display -->
      <template v-else>
        <div
          v-for="(value, key) in data"
          :key="key"
          class="info-row"
        >
          <span class="info-label">{{ key }}:</span>
          <span
            class="info-value"
            :class="{ 'error': value === 'Data unavailable' || value === 'Not available' }"
          >
            {{ value }}
          </span>
        </div>
      </template>

      <!-- Optional Footer Slot -->
      <slot name="footer"></slot>
    </div>
  </div>
</template>

<script>
export default {
  name: 'SystemCard',
  props: {
    title: {
      type: String,
      required: true
    },
    icon: {
      type: String,
      default: 'fa-info-circle'
    },
    data: {
      type: Object,
      default: null
    },
    loading: {
      type: Boolean,
      default: false
    }
  }
}
</script>

<style scoped>
.system-card {
  background-color: var(--ark-color-white);
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: box-shadow 0.2s ease;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  min-height: 200px;
}

.system-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.card-header {
  display: flex;
  align-items: center;
  padding: 14px 18px;
  background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
  border-bottom: 1px solid #e0e0e0;
  gap: 10px;
}

.header-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--ark-color-black);
}

.icon-color {
  color: var(--ark-color-grey);
  font-size: 1.2rem;
}

.card-content {
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
}

.loading-state,
.no-data-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 24px;
  color: #666;
}

.loading-state i {
  font-size: 1.5rem;
  color: var(--ark-color-blue);
}

.no-data-state i {
  font-size: 1.5rem;
  color: #999;
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 0;
  border-bottom: 1px solid #f0f0f0;
}

.info-row:last-child {
  border-bottom: none;
}

.info-label {
  font-weight: 500;
  color: #555;
  font-size: 0.95rem;
}

.info-value {
  color: var(--ark-color-black);
  text-align: right;
  max-width: 65%;
  font-size: 0.95rem;
  word-wrap: break-word;
  white-space: normal;
  overflow-wrap: break-word;
}

.info-value.error {
  color: #999;
  font-style: italic;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
