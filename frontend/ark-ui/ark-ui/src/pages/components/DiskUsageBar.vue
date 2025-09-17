<template>
  <div class="disk-usage-bar">
    <div class="usage-header">
      <span class="usage-label">Disk Usage</span>
      <span class="usage-percentage" :class="usageClass">
        {{ percentage }}%
      </span>
    </div>
    <div class="usage-bar-wrapper">
      <div
        class="usage-bar"
        :class="usageClass"
        :style="{ width: `${percentage}%` }"
      />
    </div>
    <div class="usage-details">
      <span>{{ used.toFixed(1) }} GB used</span>
      <span>{{ (total - used).toFixed(1) }} GB free</span>
    </div>
  </div>
</template>

<script>
export default {
  name: 'DiskUsageBar',
  props: {
    used: {
      type: Number,
      required: true
    },
    total: {
      type: Number,
      required: true
    }
  },
  computed: {
    percentage() {
      if (this.total === 0) return 0;
      return Math.round((this.used / this.total) * 100);
    },

    usageClass() {
      if (this.percentage >= 90) return 'critical';
      if (this.percentage >= 80) return 'warning';
      return 'normal';
    }
  }
}
</script>

<style scoped>
.disk-usage-bar {
  width: 100%;
  padding-top: 12px;
  border-top: 1px solid var(--ark-color-light-grey);
}

.usage-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.usage-label {
  font-weight: 500;
  color: var(--ark-color-grey);
  font-size: 0.9rem;
}

.usage-percentage {
  font-weight: 600;
  font-size: 0.95rem;
}

.usage-percentage.normal {
  color: var(--ark-color-green);
}

.usage-percentage.warning {
  color: var(--ark-color-orange);
}

.usage-percentage.critical {
  color: var(--ark-color-red);
}

.usage-bar-wrapper {
  width: 100%;
  height: 10px;
  background-color: var(--ark-color-light-grey);
  border-radius: 5px;
  overflow: hidden;
  margin-bottom: 8px;
}

.usage-bar {
  height: 100%;
  border-radius: 5px;
  transition: width 0.3s ease, background 0.3s ease;
}

.usage-bar.normal {
  background: var(--ark-color-green);
}

.usage-bar.warning {
  background: var(--ark-color-orange);
}

.usage-bar.critical {
  background: var(--ark-color-red);
}

.usage-details {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
  color: var(--ark-color-grey);
}
</style>
