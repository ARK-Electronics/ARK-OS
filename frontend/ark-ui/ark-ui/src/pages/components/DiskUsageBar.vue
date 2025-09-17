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
  border-top: 1px solid #f0f0f0;
}

.usage-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.usage-label {
  font-weight: 500;
  color: #666;
  font-size: 0.9rem;
}

.usage-percentage {
  font-weight: 600;
  font-size: 0.95rem;
}

.usage-percentage.normal {
  color: #4caf50;
}

.usage-percentage.warning {
  color: #ff9800;
}

.usage-percentage.critical {
  color: #f44336;
}

.usage-bar-wrapper {
  width: 100%;
  height: 10px;
  background-color: #e0e0e0;
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
  background: linear-gradient(90deg, #4caf50 0%, #66bb6a 100%);
}

.usage-bar.warning {
  background: linear-gradient(90deg, #ff9800 0%, #ffa726 100%);
}

.usage-bar.critical {
  background: linear-gradient(90deg, #f44336 0%, #ef5350 100%);
}

.usage-details {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
  color: #666;
}
</style>
