<template>
  <div class="temperature-gauge">
    <div class="gauge-label">{{ label }}</div>
    <div class="gauge-display">
      <svg class="gauge-svg" viewBox="0 0 100 60">
        <!-- Background arc -->
        <path
          class="gauge-background"
          :d="backgroundPath"
        />
        <!-- Value arc -->
        <path
          class="gauge-value"
          :class="gaugeClass"
          :d="valuePath"
        />
      </svg>
      <div class="gauge-reading">
        <span class="temperature-value">{{ value.toFixed(1) }}</span>
        <span class="temperature-unit">°C</span>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'TemperatureGauge',
  props: {
    label: {
      type: String,
      required: true
    },
    value: {
      type: Number,
      required: true
    },
    max: {
      type: Number,
      default: 100
    },
    warning: {
      type: Number,
      default: 70
    },
    critical: {
      type: Number,
      default: 85
    }
  },
  computed: {
    percentage() {
      return Math.min((this.value / this.max) * 100, 100);
    },

    gaugeClass() {
      if (this.value >= this.critical) return 'critical';
      if (this.value >= this.warning) return 'warning';
      return 'normal';
    },

    backgroundPath() {
      return this.describeArc(50, 50, 35, -180, 0);
    },

    valuePath() {
      const endAngle = -180 + (this.percentage * 1.8);
      return this.describeArc(50, 50, 35, -180, endAngle);
    }
  },
  methods: {
    describeArc(x, y, radius, startAngle, endAngle) {
      const start = this.polarToCartesian(x, y, radius, endAngle);
      const end = this.polarToCartesian(x, y, radius, startAngle);
      const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";

      return [
        "M", start.x, start.y,
        "A", radius, radius, 0, largeArcFlag, 0, end.x, end.y
      ].join(" ");
    },

    polarToCartesian(centerX, centerY, radius, angleInDegrees) {
      const angleInRadians = (angleInDegrees - 90) * Math.PI / 180.0;
      return {
        x: centerX + (radius * Math.cos(angleInRadians)),
        y: centerY + (radius * Math.sin(angleInRadians))
      };
    }
  }
}
</script>

<style scoped>
.temperature-gauge {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 80px;
}

.gauge-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--ark-color-grey);
  margin-bottom: 4px;
  text-transform: uppercase;
}

.gauge-display {
  position: relative;
  width: 80px;
  height: 50px;
}

.gauge-svg {
  width: 100%;
  height: 100%;
}

.gauge-background {
  fill: none;
  stroke: var(--ark-color-light-grey);
  stroke-width: 8;
  stroke-linecap: round;
}

.gauge-value {
  fill: none;
  stroke-width: 8;
  stroke-linecap: round;
  transition: stroke 0.3s ease;
}

.gauge-value.normal {
  stroke: var(--ark-color-green);
}

.gauge-value.warning {
  stroke: var(--ark-color-orange);
}

.gauge-value.critical {
  stroke: var(--ark-color-red);
}

.gauge-reading {
  position: absolute;
  bottom: 0;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  align-items: baseline;
  gap: 2px;
}

.temperature-value {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--ark-color-black);
}

.temperature-unit {
  font-size: 0.75rem;
  color: var(--ark-color-grey);
}
</style>
