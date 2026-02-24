#!/bin/bash
# Enable nginx site and reload
ln -sf /etc/nginx/sites-available/ark-ui /etc/nginx/sites-enabled/ark-ui
rm -f /etc/nginx/sites-enabled/default 2>/dev/null
nginx -t && systemctl reload nginx
