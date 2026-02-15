# Zapret2 SSH Tunnel One-Click

Menu-driven Bash manager for building and maintaining obfuscated SSH tunnels on Ubuntu/Debian with `zapret2`.

## What is new

- Multi-target tunneling support
- Different local ports can tunnel to different foreign servers
- One `systemd` unit per target (`ssh-tunnel-<name>.service`)
- Persistent management menu you can open anytime
- Add/remove/list/restart targets without reinstalling everything
- A tunnel dashboard (summary + drill-down per tunnel)

## Features

- Interactive menu for setup and lifecycle management
- Root check and package automation (`sshpass`, `curl`, `wget`, `net-tools`, `openssh-client` if needed)
- Optional destructive initial setup (iptables flush/reset + service cleanup) with typed confirmation
- Zapret2 install/start automation
- NFQUEUE rule automation per SSH destination port
- SSH key creation + optional `ssh-copy-id` automation
- End-to-end service and listening-port verification
- Pretty dashboard view: SVC state, local listen ratio, and quick SSH connectivity check
- Per-tunnel bind address selection (`127.0.0.1` recommended, or `0.0.0.0` for public)
- Edit tunnels in-place (rename, ports, host/port, bind address)

## Requirements

- Ubuntu/Debian server
- Root access
- Reachable foreign SSH servers

## Quick Run (Menu)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh)
```

Alternative with `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh | bash
```

## Install Persistent Command

From inside the menu choose option `9`, or run directly:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh) --install-command
```

Then you can always open the manager using:

```bash
sudo zapret2-tunnel
```

## Direct Modes

```bash
sudo ./setup_zapret2_tunnel.sh --menu
sudo ./setup_zapret2_tunnel.sh --initial-setup
sudo ./setup_zapret2_tunnel.sh --add-target
sudo ./setup_zapret2_tunnel.sh --edit
sudo ./setup_zapret2_tunnel.sh --dashboard
sudo ./setup_zapret2_tunnel.sh --profile
sudo ./setup_zapret2_tunnel.sh --restart-all
sudo ./setup_zapret2_tunnel.sh --install-command
```

## Dashboard

Use menu option `6` (or `--dashboard`) to see a clean overview per tunnel, then select a tunnel to view details.

## Zapret2 Profiles

The manager can switch `/etc/zapret2.lua` between three profiles:

- Profile 1: `scripts/fake.lua`
- Profile 2: `scripts/split.lua`
- Profile 3: `scripts/disorder.lua`

The script will use a local file next to the script if available; otherwise it downloads from this repo’s raw files (it checks repo root and `/scripts/`).
## Naming

When adding a tunnel, you choose a friendly name (examples: `Sweden`, `UK`, `Germany-1`).
The manager derives a safe key from it (used for systemd unit names).

## Bind Address

Each tunnel’s local forwards can bind to:

- `127.0.0.1` (recommended): only accessible locally on the server
- `0.0.0.0`: accessible on all interfaces (public)

## Multi-Server Mapping Example

- Local port `31` -> Sweden server
- Local port `32` -> UK server
- Local port `4000` -> Germany server

Add each target from menu option `2` with its own server IP, SSH port, and local port list.

## Managed Files

- Main script: `setup_zapret2_tunnel.sh`
- Mirror copy: `scripts/setup_zapret2_tunnel.sh`
- Config store: `/etc/ssh-tunnel-manager/targets.conf`
- Tunnel units: `/etc/systemd/system/ssh-tunnel-<key>.service`
- Manager command: `/usr/local/sbin/zapret2-tunnel`

## Security Notes

- Root passwords are only used for `ssh-copy-id` when you choose that option.
- Password variables are unset after key copy.
- For hardening, disable password SSH login on foreign servers after key setup.

## License

MIT
