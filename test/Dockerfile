# syntax=docker/dockerfile:1
#
# Local x86 test image for the ARK-OS userspace stack: the four Python managers + the
# Express gateway + nginx serving the built Vue UI. No camera, no flight controller, no
# systemd. Build context is the repo root (see test/docker-compose.yml). See test/README.md.

# --- build the Vue UI -> dist/ ------------------------------------------------------
FROM node:20-slim AS frontend
WORKDIR /app
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- install the gateway's production node_modules ----------------------------------
FROM node:20-slim AS gateway
WORKDIR /gw
COPY services/ark-ui-backend/package.json ./
RUN npm install --omit=dev
COPY services/ark-ui-backend/ ./

# --- runtime: python managers + node gateway + nginx + supervisord ------------------
FROM python:3.11-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx supervisor gcc python3-dev \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

# Manager Python deps (mirrors packaging/build_venv.sh).
RUN pip install --no-cache-dir \
      pymavlink dronecan fastapi uvicorn python-multipart psutil toml pyyaml pyserial

# Node runtime + the gateway with its installed deps.
COPY --from=gateway /usr/local/bin/node /usr/local/bin/node
COPY --from=gateway /gw /usr/lib/ark-os/ark-ui-backend

# The four in-repo manager services.
COPY services/system-manager/     /usr/lib/ark-os/python/system-manager/
COPY services/service-manager/    /usr/lib/ark-os/python/service-manager/
COPY services/connection-manager/ /usr/lib/ark-os/python/connection-manager/
COPY services/autopilot-manager/  /usr/lib/ark-os/python/autopilot-manager/

# Built UI.
COPY --from=frontend /app/dist /var/www/ark-ui/html

# Harness bits: nginx site, supervisord config, fake FC, systemctl/journalctl shims.
COPY test/nginx.conf /etc/nginx/conf.d/ark-ui.conf
COPY test/supervisord.conf /etc/supervisord.conf
COPY test/mavlink_stub.py /usr/lib/ark-os/test/mavlink_stub.py
COPY test/bin/systemctl test/bin/journalctl /usr/local/bin/
RUN chmod +x /usr/local/bin/systemctl /usr/local/bin/journalctl \
 && mkdir -p /usr/lib/ark-os/manifests /etc/ark-os /run/ark-os-test

EXPOSE 80
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
