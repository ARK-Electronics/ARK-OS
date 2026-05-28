#!/usr/bin/env bash
# Build the Vue.js frontend and install the backend's production dependencies,
# staging both into the package tree. Invoked by build.sh.
set -euo pipefail

cd "$REPO_ROOT"

HTML_DIR="$BUILD_DIR/var/www/ark-ui/html"
BACKEND_DIR="$BUILD_DIR$PKG_PREFIX/ark-ui-backend"
mkdir -p "$HTML_DIR" "$BACKEND_DIR"

echo "==> building Vue frontend (vue-cli-service build -> dist/)"
( cd frontend/ark-ui/ark-ui
  npm install            # no lockfile; pulls @vue/cli-service from devDependencies
  npm run build )
cp -r frontend/ark-ui/ark-ui/dist/. "$HTML_DIR/"

echo "==> installing backend production dependencies"
( cd frontend/ark-ui/backend
  npm install --omit=dev )
# Ship the backend source + node_modules; the unit runs `node index.js` here.
cp -r frontend/ark-ui/backend/. "$BACKEND_DIR/"

echo "==> frontend staged: $HTML_DIR"
echo "==> backend staged:  $BACKEND_DIR"
