<template>
  <div class="editor-backdrop">
    <div class="editor-container">
      <div class="editor-content">
        <h1>{{ serviceName }}</h1>

        <div class="toml-editor">
          <!-- Top-level primitive values first -->
          <div v-for="(value, key) in topLevelPrimitives" :key="key" class="form-group">
            <label :for="key">{{ formatKey(key) }}</label>

            <!-- String input -->
            <input
              v-if="typeof value === 'string'"
              type="text"
              :id="key"
              v-model="config[key]"
              class="text-input"
            />

            <!-- Boolean input -->
            <div v-else-if="typeof value === 'boolean'" class="checkbox-group">
              <input
                type="checkbox"
                :id="key"
                v-model="config[key]"
                class="checkbox-input"
              />
            </div>

            <!-- Number input -->
            <input
              v-else-if="typeof value === 'number'"
              type="number"
              :id="key"
              v-model.number="config[key]"
              class="number-input"
              step="any"
            />
          </div>

          <!-- Then display each sub-table with a section header -->
          <div v-for="(tableValue, tableKey) in subTables" :key="tableKey" class="subtable-section">
            <div class="subtable-header">
              {{ formatKey(tableKey) }}
            </div>

            <div class="subtable-content">
              <div
                v-for="subKey in getNonOptionsKeys(tableValue)"
                :key="`${tableKey}.${subKey}`"
                class="form-group"
              >
                <label :for="`${tableKey}.${subKey}`">{{ formatKey(subKey) }}</label>

                <!-- Dropdown using options array if available -->
                <select
                  v-if="hasOptionsArray(tableKey, subKey)"
                  :id="`${tableKey}.${subKey}`"
                  v-model="config[tableKey][subKey]"
                  class="select-input"
                >
                  <option
                    v-for="option in getOptionsArray(tableKey, subKey)"
                    :key="option"
                    :value="option"
                  >
                    {{ option }}
                  </option>
                </select>

                <!-- String input -->
                <input
                  v-else-if="typeof tableValue[subKey] === 'string'"
                  type="text"
                  :id="`${tableKey}.${subKey}`"
                  v-model="config[tableKey][subKey]"
                  class="text-input"
                />

                <!-- Boolean input -->
                <div v-else-if="typeof tableValue[subKey] === 'boolean'" class="checkbox-group">
                  <input
                    type="checkbox"
                    :id="`${tableKey}.${subKey}`"
                    v-model="config[tableKey][subKey]"
                    class="checkbox-input"
                  />
                </div>

                <!-- Number input -->
                <input
                  v-else-if="typeof tableValue[subKey] === 'number'"
                  type="number"
                  :id="`${tableKey}.${subKey}`"
                  v-model.number="config[tableKey][subKey]"
                  class="number-input"
                  step="any"
                />

                <!-- Simple array display (read-only for now) -->
                <div v-else-if="Array.isArray(tableValue[subKey])" class="array-display">
                  {{ JSON.stringify(tableValue[subKey]) }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="actions-container">
        <div class="actions">
          <button @click="saveConfig" class="save-button">Save</button>
          <button @click="cancelEdit" class="cancel-button">Cancel</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import toml from 'toml-js';

export default {
  name: 'TomlEditor',
  props: {
    serviceName: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      config: {},
      originalConfig: null,
      originalTypes: {} // Map to store original types
    };
  },
  computed: {
    // Separate top-level primitives from sub-tables
    topLevelPrimitives() {
      const primitives = {};
      Object.entries(this.config).forEach(([key, value]) => {
        if (!this.isObject(value)) {
          primitives[key] = value;
        }
      });
      return primitives;
    },
    // Get all sub-tables (nested objects)
    subTables() {
      const tables = {};
      Object.entries(this.config).forEach(([key, value]) => {
        if (this.isObject(value)) {
          tables[key] = value;
        }
      });
      return tables;
    }
  },
  mounted() {
    this.loadConfig();
  },
  methods: {
    isObject(value) {
      return typeof value === 'object' && value !== null && !Array.isArray(value);
    },

    // Check if a field is an options array (ends with _options)
    isOptionsField(key) {
      return key.endsWith('_options');
    },

    // Get all keys that aren't options fields
    getNonOptionsKeys(obj) {
      return Object.keys(obj).filter(key => !this.isOptionsField(key));
    },

    // Get the base field name for an options field
    getBaseFieldName(optionsKey) {
      return optionsKey.replace('_options', '');
    },

    // Check if a field has a corresponding options array
    hasOptionsArray(tableKey, fieldKey) {
      const optionsKey = `${fieldKey}_options`;
      return (
        this.config[tableKey] &&
        Array.isArray(this.config[tableKey][optionsKey])
      );
    },

    // Get the options array for a field
    getOptionsArray(tableKey, fieldKey) {
      const optionsKey = `${fieldKey}_options`;
      return this.config[tableKey][optionsKey] || [];
    },

    // Store original types when config is loaded
    storeOriginalTypes(obj, path = '') {
      for (const key in obj) {
        const fullPath = path ? `${path}.${key}` : key;
        const value = obj[key];

        if (value && typeof value === 'object' && !Array.isArray(value)) {
          this.storeOriginalTypes(value, fullPath);
        } else {
          this.originalTypes[fullPath] = typeof value;
        }
      }
    },

    // Validate that all fields still match their original types
    validateTypes() {
      const invalidFields = [];

      const checkTypes = (obj, path = '') => {
        for (const key in obj) {
          const fullPath = path ? `${path}.${key}` : key;
          const value = obj[key];

          if (value && typeof value === 'object' && !Array.isArray(value)) {
            checkTypes(value, fullPath);
          } else if (this.originalTypes[fullPath]) {
            const originalType = this.originalTypes[fullPath];
            const currentType = typeof value;

            if (originalType === 'number' && currentType !== 'number') {
              // Check if it can be converted to a number
              const numValue = Number(value);
              if (isNaN(numValue)) {
                invalidFields.push({
                  path: fullPath,
                  expectedType: originalType,
                  currentType: currentType,
                  value: value
                });
              }
            }
          }
        }
      };

      checkTypes(this.config);
      return invalidFields;
    },

    loadConfig() {
      console.log(`Loading config for service: ${this.serviceName}`);
      axios
        .get(`/api/service/config?serviceName=${this.serviceName}`)
        .then((response) => {
          const status = response.data.status;
          const configData = response.data.data;

          if (status === 'success') {
            try {
              this.config = toml.parse(configData.trim());

              // Store the original data types
              this.originalTypes = {};
              this.storeOriginalTypes(this.config);

              // Store original config for comparison or reset
              this.originalConfig = JSON.parse(JSON.stringify(this.config));
            } catch (error) {
              console.error('Error parsing TOML:', error);
            }
          } else {
            console.error('Failed to load config:', configData);
          }
        })
        .catch((error) => {
          console.error('Error fetching config from API:', error);
        });
    },

    saveConfig() {
      try {
        // Validate types before saving
        const invalidFields = this.validateTypes();

        if (invalidFields.length > 0) {
          // Format error message
          const errorMessages = invalidFields.map(field => {
            const fieldName = field.path.split('.').pop();
            return `"${fieldName}" should be a number but contains "${field.value}"`;
          });

          alert(`Please fix the following issues before saving:\n\n${errorMessages.join('\n')}`);
          return;
        }

        // All validations passed, prepare to save
        const configToSave = JSON.parse(JSON.stringify(this.config));

        // Convert numeric strings to actual numbers
        const convertTypes = (obj) => {
          for (const key in obj) {
            const value = obj[key];

            if (value && typeof value === 'object' && !Array.isArray(value)) {
              convertTypes(value);
            } else if (typeof value === 'string') {
              // Check if this was originally a number
              const fullPath = this.getFullPath(obj, key);
              if (fullPath && this.originalTypes[fullPath] === 'number') {
                const numValue = Number(value);
                if (!isNaN(numValue)) {
                  obj[key] = numValue;
                }
              }
            }
          }
        };

        // Convert any string values back to numbers where needed
        convertTypes(configToSave);

        const tomlString = toml.dump(configToSave);

        axios.post(`/api/service/config?serviceName=${this.serviceName}`,
          JSON.stringify({ config: tomlString }),
          { headers: { 'Content-Type': 'application/json' } }
        )
        .then((response) => {
          if (response.data.status === 'success') {
            this.$emit('close-editor');
            this.$emit('config-saved');
          } else {
            console.error('Error saving config:', response.data.data);
            alert('Error saving configuration');
          }
        })
        .catch((error) => {
          console.error('Error saving config:', error);
          alert('Error saving configuration');
        });
      } catch (error) {
        console.error('Error converting to TOML:', error);
        alert('Error preparing configuration for saving');
      }
    },

    // Helper to get the full path of a nested property
    getFullPath(obj, key) {
      for (const path in this.originalTypes) {
        const parts = path.split('.');
        const lastPart = parts[parts.length - 1];

        if (lastPart === key) {
          // Check if this is actually the right object
          let currentObj = this.config;
          let found = true;

          for (let i = 0; i < parts.length - 1; i++) {
            if (currentObj[parts[i]] === undefined) {
              found = false;
              break;
            }
            currentObj = currentObj[parts[i]];
          }

          if (found && currentObj === obj) {
            return path;
          }
        }
      }
      return null;
    },

    cancelEdit() {
      this.$emit('close-editor');
    },

    formatKey(key) {
      // Capitalize first letter and replace underscores with spaces
      return key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
    }
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
  width: 600px;
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

.toml-editor {
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--ark-color-black);
}

.text-input,
.number-input,
.select-input {
  width: 100%;
  padding: 10px;
  box-sizing: border-box;
  border: 2px solid var(--ark-color-black-shadow);
  border-radius: 6px;
  font-size: 16px;
  color: var(--ark-color-black);
}

.select-input {
  background-color: var(--ark-color-white);
  height: 42px;
  cursor: pointer;
}

.number-input {
  font-family: monospace;
}

.checkbox-group {
  display: flex;
  align-items: center;
  margin-top: 10px;
}

.checkbox-input {
  transform: scale(1.5);
  margin-right: 10px;
}

.array-display {
  padding: 10px;
  background-color: var(--ark-color-black-shadow);
  border-radius: 6px;
  font-family: monospace;
  white-space: pre-wrap;
  word-break: break-all;
}

.subtable-section {
  margin-top: 30px;
  margin-bottom: 25px;
}

.subtable-header {
  background-color: var(--ark-color-black-shadow);
  padding: 12px 15px;
  border-radius: 6px;
  font-weight: 600;
  color: var(--ark-color-black);
  margin-bottom: 15px;
  text-transform: uppercase;
  letter-spacing: 1px;
  font-size: 14px;
}

.subtable-content {
  padding: 0 10px;
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
  transition: background-color 0.3s ease;
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
</style>
