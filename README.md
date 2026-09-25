# DecoMonitor

Local bandwidth dashboard for a TP-Link Deco mesh. One process polls the Deco about once a second, stores speeds and usage in `history.sqlite`, and serves the page at http://127.0.0.1:8787.

The Deco owner password stays in `secret.txt` on this machine. It is never sent to TP-Link's cloud. The app does not change SSIDs, DHCP, or node roles.

Copy `config.example.json` to `config.json` and set `host` to the Deco's LAN address (often `192.168.68.1`) before the first start. Python 3.11 or newer is required.

## Windows

From an elevated PowerShell, in this folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

That creates `.venv`, installs dependencies, and registers the scheduled task `DecoBandwidth` to run as SYSTEM at startup, including when nobody is logged on. Open http://127.0.0.1:8787 after you sign in. If `secret.txt` is missing, the page asks for the owner TP-Link ID password once.

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

Uninstall removes the task and leaves `secret.txt` and `history.sqlite`.

## Linux

Boot recording (no login required):

```sh
sudo ./install.sh
```

That creates a system user `decomonitor` and enables the systemd service `decomonitor.service`.

Without root, `./install.sh` installs a user service that starts at login. The script says so when it does that.

```sh
sudo ./uninstall.sh
```

Uninstall removes the service and leaves `secret.txt` and `history.sqlite`.
