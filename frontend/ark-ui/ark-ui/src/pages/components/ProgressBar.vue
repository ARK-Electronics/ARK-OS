<template>
  <div class="progress-container">
    <div class="progress-header">
      <span class="progress-label">{{ label }}</span>
      <span v-if="showPercentage" class="progress-value">{{ value.toFixed(1) }}%</span>
    </div>
    <div class="progress-bar-wrapper">
      <div
        class="progress-bar"
        :class="progressClass"
        :style="{ width: `${Math.min(value, 100)}%` }"
      />
    </div>
  </div>
</template>

<script>
export default {
  name: 'ProgressBar',
  props: {
    label: {
      type: String,
      required: true
    },
    value: {
      type: Number,
      required: true
    },
    showPercentage: {
      type: Boolean,
      default: true
    },
    warningThreshold: {
      type: Number,
      default: 70
    },
    criticalThreshold: {
      type: Number,
      default: 85
    }
  },
  computed: {
    progressClass() {
      if (this.value >= this.criticalThreshold) return 'critical';
      if (this.value >= this.warningThreshold) return 'warning';
      return 'normal';
    }
  }
}
</script>

<style scoped>
.progress-container {
  width: 100%;
}

.progress-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 6px;
  font-size: 0.9rem;
}

.progress-label {
  color: #666;
  font-weight: 500;
}

.progress-value {
  color: #333;
  font-weight: 600;
}

.progress-bar-wrapper {
  width: 100%;
  height: 8px;
  background-color: #e0e0e0;
  border-radius: 4px;
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease, background-color 0.3s ease;
}

.progress-bar.normal {
  background: linear-gradient(90deg, #4caf50 0%, #66bb6a 100%);
}

.progress-bar.warning {
  background: linear-gradient(90deg, #ff9800 0%, #ffa726 100%);
}

.progress-bar.critical {
  background: linear-gradient(90deg, #f44336 0%, #ef5350 100%);
}
</style>
