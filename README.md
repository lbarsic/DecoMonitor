# DecoMonitor

Local bandwidth dashboard for a TP-Link Deco mesh. One process polls the Deco about once a second, stores speeds and usage in `history.sqlite`, and serves the page at http://127.0.0.1:8787.

The Deco owner password stays in `secret.txt` on that PC. It is never sent to TP-Link's cloud. The app does not change SSIDs, DHCP, or node roles.

## Windows

Download the latest `DecoMonitor-<version>.exe` from the [releases page](https://github.com/lbarsic/DecoMonitor/releases/latest) and open it.

Approve the administrator prompt. The app is copied to `C:\ProgramData\DecoMonitor` and a startup task named `DecoMonitor` runs it at every boot, before anyone logs on. The dashboard opens at http://127.0.0.1:8787. The first page asks for the Deco address (usually `192.168.68.1`) and the owner TP-Link ID password.

Windows may say the file is unrecognized because it is not signed. Choose More info, then Run anyway.

To remove the startup task later, open an elevated PowerShell and run:

```powershell
& (Get-ChildItem "$env:ProgramData\DecoMonitor\DecoMonitor*.exe" | Select-Object -First 1).FullName --uninstall
```

That removes the task and leaves the saved history and password in `C:\ProgramData\DecoMonitor`.

A push to `main` builds `DecoMonitor-<version>.exe` and publishes it as the latest GitHub release. An installed copy looks for a release about 30 seconds after it starts, and then about every 12 hours. **Check for updates** looks immediately. The page reports a newer release and waits. **Download update** asks before downloading. **Install update** asks again and warns that the server will restart. Saved history and the password stay in place. Replacing the running program cannot be done without that restart.

## Linux

Boot recording (no login required):

```sh
sudo ./install.sh
```

That creates a system user `decomonitor` and enables the systemd service `decomonitor.service`. Copy `config.example.json` to `config.json` first and set `host` if the Deco is not at `192.168.68.1`.

Without root, `./install.sh` installs a user service that starts at login. The script says so when it does that.

```sh
sudo ./uninstall.sh
```

Uninstall removes the service and leaves `secret.txt` and `history.sqlite`.
