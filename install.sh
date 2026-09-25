#!/bin/sh
# Install DecoMonitor and start it at boot.
# Root: system user "decomonitor" and a system service (starts with no login).
# Otherwise: a user service, which starts at login. Re-running keeps secret.txt and history.sqlite.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
PYTHON=${PYTHON:-python3}

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required." >&2
  exit 1
fi

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  "$PYTHON" -m venv "$ROOT/.venv"
fi
"$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"

if [ -f "$ROOT/secret.txt" ]; then
  chmod 600 "$ROOT/secret.txt"
fi

write_unit() {
  dest=$1
  run_user=$2
  wanted=$3
  {
    echo "[Unit]"
    echo "Description=Deco bandwidth monitor"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    echo "Type=simple"
    if [ -n "$run_user" ]; then
      echo "User=$run_user"
    fi
    echo "WorkingDirectory=$ROOT"
    echo "ExecStart=$ROOT/.venv/bin/python $ROOT/server.py"
    echo "Restart=always"
    echo "RestartSec=3"
    echo
    echo "[Install]"
    echo "WantedBy=$wanted"
  } > "$dest"
}

if [ "$(id -u)" -eq 0 ]; then
  if ! id decomonitor >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      nologin=/usr/sbin/nologin
      [ -x "$nologin" ] || nologin=/sbin/nologin
      useradd --system --home-dir "$ROOT" --shell "$nologin" decomonitor
    elif command -v adduser >/dev/null 2>&1; then
      adduser -S -h "$ROOT" -s /sbin/nologin decomonitor
    else
      echo "Could not create the decomonitor user." >&2
      exit 1
    fi
  fi
  chown -R decomonitor:decomonitor "$ROOT"
  if [ -f "$ROOT/secret.txt" ]; then
    chmod 600 "$ROOT/secret.txt"
  fi
  write_unit /etc/systemd/system/decomonitor.service decomonitor multi-user.target
  systemctl daemon-reload
  systemctl enable --now decomonitor.service
  echo "DecoMonitor starts at boot. Dashboard: http://127.0.0.1:8787"
else
  mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  dest="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/decomonitor.service"
  write_unit "$dest" "" default.target
  systemctl --user daemon-reload
  systemctl --user enable --now decomonitor.service
  echo "Installed as a user service. It starts when this user logs in."
  echo "To record from machine boot with nobody logged in, run sudo ./install.sh"
  echo "Dashboard: http://127.0.0.1:8787"
fi
