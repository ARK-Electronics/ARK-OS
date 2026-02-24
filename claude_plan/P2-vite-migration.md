# P2: Migrate Frontend from vue-cli-service to Vite

## Problem

The ARK UI frontend uses `vue-cli-service` (webpack-based) for building. Vue CLI is in
maintenance mode — the Vue ecosystem has moved to Vite, which offers:
- 10-50x faster dev server startup (native ESM, no bundling in dev)
- Faster production builds (Rollup-based)
- Better Vue 3 integration
- Active maintenance and ecosystem support

## Solution

Migrate the frontend build tooling from vue-cli-service to Vite while keeping the
existing Vue components unchanged.

## Files to Modify

| File | Change |
|------|--------|
| `frontend/ark-ui/ark-ui/package.json` | Replace vue-cli deps with vite + @vitejs/plugin-vue |
| `frontend/ark-ui/ark-ui/vite.config.js` | New Vite config (replaces vue.config.js) |
| `frontend/ark-ui/ark-ui/vue.config.js` | Delete |
| `frontend/ark-ui/ark-ui/index.html` | Move from public/ to root, add `<script type="module">` |
| `frontend/ark-ui/ark-ui/src/main.js` | May need minor import adjustments |
| `.github/workflows/build.yml` | Verify npm build command still works |

## Implementation Steps

### Step 1: Create Vite config

```js
// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 8080,  // Match current dev server port
    proxy: {
      '/api': {
        target: 'http://localhost:80',
        changeOrigin: true,
      }
    }
  },
  build: {
    outDir: 'dist',
  }
})
```

### Step 2: Update package.json

```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "vue": "^3.x",
    // ... existing deps unchanged
  },
  "devDependencies": {
    "@vitejs/plugin-vue": "^5.0.0",
    "vite": "^6.0.0"
    // Remove: @vue/cli-service, @vue/cli-plugin-*
  }
}
```

### Step 3: Move index.html

Vite requires `index.html` at the project root (not in `public/`):

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ARK UI</title>
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/src/main.js"></script>
</body>
</html>
```

### Step 4: Update import paths

Vite uses native ESM, so some imports may need adjustment:
- `require()` → `import`
- Environment variables: `process.env.VUE_APP_*` → `import.meta.env.VITE_*`

### Step 5: Update CI build command

In `.github/workflows/build.yml`, the build step should still work if `npm run build`
is already used. Verify the output goes to `dist/` as expected.

### Step 6: Test production build

```bash
cd frontend/ark-ui/ark-ui
npm install
npm run build
# Verify dist/ contains the expected static files
# Verify the built app works when served by nginx
```

## Acceptance Criteria

- [ ] `npm run dev` starts Vite dev server successfully
- [ ] `npm run build` produces production bundle in `dist/`
- [ ] All existing pages and components work identically
- [ ] API proxy works in development mode
- [ ] CI build completes successfully
- [ ] Built files serve correctly from nginx on device
- [ ] No vue-cli-service dependencies remain in package.json

## Dependencies

None — can be done independently.

## Effort Estimate

Small. This is a well-documented migration path. The main risk is environment variable
renaming and any `require()` calls that need to become `import`. Estimate 1-2 sessions.
