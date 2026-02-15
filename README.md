# Zapret2 SSH Tunnel One-Click

Menu-driven Bash manager for building and maintaining obfuscated SSH tunnels on Ubuntu/Debian with `zapret2`.

## What is new

- Multi-target tunneling support
- Different local ports can tunnel to different foreign servers
- One `systemd` unit per target (`ssh-tunnel-<name>.service`)
- Persistent management menu you can open anytime
- Add/remove/list/restart targets without reinstalling everything

## Features

- Interactive menu for setup and lifecycle management
- Root check and package automation (`sshpass`, `curl`, `wget`, `net-tools`, `openssh-client` if needed)
- Optional destructive initial setup (iptables flush/reset + service cleanup)
- Zapret2 install/start automation
- NFQUEUE rule automation per SSH destination port
- SSH key creation + optional `ssh-copy-id` automation
- End-to-end service and listening-port verification

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

From inside the menu choose option `7`, or run directly:

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
sudo ./setup_zapret2_tunnel.sh --status
sudo ./setup_zapret2_tunnel.sh --install-command
```

## Multi-Server Mapping Example

- Local port `31` -> Sweden server
- Local port `32` -> UK server
- Local port `4000` -> Germany server

Add each target from menu option `2` with its own server IP, SSH port, and local port list.

## Managed Files

- Main script: `setup_zapret2_tunnel.sh`
- Mirror copy: `scripts/setup_zapret2_tunnel.sh`
- Config store: `/etc/ssh-tunnel-manager/targets.conf`
- Tunnel units: `/etc/systemd/system/ssh-tunnel-<name>.service`
- Manager command: `/usr/local/sbin/zapret2-tunnel`

## Security Notes

- Root passwords are only used for `ssh-copy-id` when you choose that option.
- Password variables are unset after key copy.
- For hardening, disable password SSH login on foreign servers after key setup.

## License

MIT
