#!/bin/bash
rm -f /etc/nginx/sites-enabled/ark-ui 2>/dev/null
nginx -t && systemctl reload nginx 2>/dev/null || true
