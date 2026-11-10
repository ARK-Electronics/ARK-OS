# Adding your own service to ARK-OS

The web UI's **Services** page lists every service that has an ARK-OS manifest, not only the ones ARK-OS ships. An add-on service gets the same controls as a built-in one: start/stop, the Autostart toggle, live journal logs, and (optionally) a form editor for its TOML config.

This directory is a working example: `hello-ark`, a small script that logs a configurable message. Copy its layout for your own application.

## Requirements

Use one name, `<name>`, everywhere: it is the unit name, the manifest's filename, and the name the card shows on the Services page.

| What | Where | Notes |
|------|-------|-------|
| systemd **system** unit | `/etc/systemd/system/<name>.service` | Not a user unit (`~/.config/systemd/user`). Has an `[Install]` section. |
| Manifest | `/usr/lib/ark-os/manifests/<name>.manifest.json` | Its presence is what makes the service appear and lets the web UI control it. |
| Config (optional) | `/etc/ark-os/<configFile>` | TOML. Group `<ark-user>`, mode `0664`. |

You don't need a polkit rule or a sudoers entry: the web UI can start, stop, enable and disable any service that has a manifest. The manifests directory is owned by root, so only root can register a service.

`<ark-user>` is the account ARK-OS runs as: `jetson` on Jetson, `pi` on Raspberry Pi, `sima` on Modalix. To read it on a device:

```
systemctl show -p User --value service-manager.service
```

### The unit

- **It must be a system unit.** ARK-OS manages its services with `systemctl`, not `systemctl --user`, so a user unit is never found.
- **Set `User=` and `Group=`.** A system unit without `User=` runs as root. Running as `<ark-user>` is simplest: that account is already in `dialout`, `gpio`, `i2c` and `netdev`.
- **Use absolute paths.** A system service gets no login environment: `~/.local/bin` is not on its `PATH`, and `~` and `%h` do not point at a user's home.
- **Use `WantedBy=multi-user.target`** in `[Install]`. The Autostart toggle runs `systemctl enable`/`disable`, which needs an `[Install]` section.
- If your service talks MAVLink through mavlink-router, add `After=mavlink-router.service`.

See [`hello-ark.service`](hello-ark.service).

### The manifest

```json
{
  "displayName": "Hello ARK",
  "description": "Example add-on service that logs a configurable message.",
  "configFile": "hello-ark.toml",
  "visible": true
}
```

| Field | Effect |
|-------|--------|
| `configFile` | Filename of the config, resolved inside `/etc/ark-os/`. The card shows the edit (pencil) button only when this is set and the file exists. Unlike the old user-service setup, there is no `config.toml` default. |
| `visible` | `false` hides the card. The service can still be managed through the service-manager API. Defaults to `true`. |
| `displayName`, `description` | Not shown by the UI today (the card shows `<name>`). Fill them in to match ARK-OS's own manifests. |

### The config file

- **It must be TOML.** The Services page opens every config except mavlink-router's in its TOML form editor.
- **Keep it flat.** The editor renders top-level keys, and keys inside one level of `[table]`, as text, number, or checkbox inputs. Arrays are shown read-only, and tables nested two levels deep are not editable.
- **Use `<key>_options` for a dropdown.** A sibling array named `<key>_options` turns `<key>` into a dropdown of those values. See [`hello-ark.toml`](hello-ark.toml).
- **Read it at startup.** Saving does not restart the service. The operator restarts it from the card (stop, then start) to apply changes.
- **Make it writable by `<ark-user>`.** The web UI saves configs as `<ark-user>`. `/etc/ark-os` is group `<ark-user>` with the setgid bit, so a new file inherits the group; give it mode `0664`.
- **Pick a filename no other service uses.** `/etc/ark-os` is one flat directory shared with ARK-OS's own configs. `<name>.toml` is a safe choice.
- **Expect the file to be rewritten.** Saving from the UI regenerates the whole file, so comments are dropped.

## Try the example

On the device, from a checkout of this repo:

```
sudo ./examples/custom-service/install.sh
```

The script fills in `<ark-user>`, installs the four files at the paths in the table above, then enables and starts `hello-ark.service`. It has a card on the Services page within a second. From the card you can:

- open the log viewer to see the message repeat every `interval_s` seconds;
- edit the config, then stop and start the service to apply it. Setting `priority` to `warning` or `err` colours the lines in the log viewer;
- turn Autostart off and on.

To remove it:

```
sudo ./examples/custom-service/install.sh --uninstall
```

## ARK-OS upgrades and removal

- **Upgrading ARK-OS leaves your files alone.** dpkg only replaces files the ARK-OS package owns, and the config merge only touches ARK-OS's own configs. Each upgrade does reset `/etc/ark-os/*` to group `<ark-user>` and mode `0664`, which is what the editor needs.
- **`apt purge` of ARK-OS deletes `/etc/ark-os`**, including your config. `apt remove` does not.
- **To ship your service as its own `.deb`**, install the same files at the same paths (the unit can go in `/lib/systemd/system/` instead), and do in your `postinst` what `install.sh` does after copying files: set the config's group and mode, `systemctl daemon-reload`, and enable the unit.

## Migrating from a user service

Before ARK-OS moved to the Debian package ([#68](https://github.com/ARK-Electronics/ARK-OS/pull/68)), the service-manager ran `systemctl --user` and looked for add-ons in the user's home directory. Those add-ons no longer show up. To move one over:

| Before | Now |
|--------|-----|
| `~/.config/systemd/user/<name>.service` | `/etc/systemd/system/<name>.service`, with `User=` and `Group=` |
| `WantedBy=default.target` | `WantedBy=multi-user.target` |
| `~/.local/share/<name>/<name>.manifest.json` | `/usr/lib/ark-os/manifests/<name>.manifest.json` |
| `~/.local/share/<name>/config.toml` (the default when `configFile` was unset) | `/etc/ark-os/<configFile>`, with `configFile` set in the manifest |

1. Stop the old unit and remove it: `systemctl --user disable --now <name>`, then delete `~/.config/systemd/user/<name>.service`.
2. Replace any `%h`, `~`, or bare command names in the unit with absolute paths, and point the program at its new config path.
3. Install the files above, then `sudo systemctl daemon-reload && sudo systemctl enable --now <name>`.

Use `sudo systemctl ...` and `journalctl -u <name>` from now on (no `--user`).

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No card for the service | The manifest's filename must be exactly `<name>.manifest.json` in `/usr/lib/ark-os/manifests/`, and `visible` must not be `false`. |
| Start fails and the card stays red | Run `sudo systemctl start <name>`. "Unit <name>.service not found" means systemd does not know the unit: check its path, and run `sudo systemctl daemon-reload` after adding or editing a unit file. Otherwise the reason is in `systemctl status <name>` and the service's logs. |
| No edit (pencil) button | `configFile` is unset in the manifest, or `/etc/ark-os/<configFile>` does not exist. |
| "Error saving configuration" | `<ark-user>` cannot write the file. Run `sudo chgrp <ark-user> /etc/ark-os/<configFile> && sudo chmod 0664 /etc/ark-os/<configFile>`. |
| The service exits with status 127 | A command in the unit or its scripts was not found. Use absolute paths. |
