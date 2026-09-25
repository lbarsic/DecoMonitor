#!/bin/sh
# Remove the DecoMonitor service. Leaves secret.txt and history.sqlite in place.
set -eu
if [ "$(id -u)" -eq 0 ]; then
  systemctl disable --now decomonitor.service 2>/dev/null || true
  rm -f /etc/systemd/system/decomonitor.service
  systemctl daemon-reload
else
  systemctl --user disable --now decomonitor.service 2>/dev/null || true
  rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/decomonitor.service"
  systemctl --user daemon-reload
fi
echo "Service removed. The database and password file were left in place."
