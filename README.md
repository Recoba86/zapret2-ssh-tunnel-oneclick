# Zapret2 SSH Tunnel One-Click

Automated, interactive Bash installer for setting up an obfuscated SSH local-forward tunnel on Ubuntu/Debian servers using `zapret2`.

## Features

- Interactive setup wizard (IP, SSH port, password, forwarding ports)
- Root check and dependency installation (`sshpass`, `curl`, `wget`, `net-tools`)
- Full `iptables` cleanup (filter/nat/mangle) and reset to ACCEPT policies
- Stops and disables existing `zapret2` / `ssh-tunnel` services
- Kills existing SSH tunnel processes safely
- Installs and enables `zapret2` service
- Adds NFQUEUE rule for SSH traffic obfuscation
- Generates SSH ed25519 key automatically (if missing)
- Configures passwordless SSH login via `ssh-copy-id` + `sshpass`
- Creates resilient `systemd` service for persistent SSH tunnel
- Final verification with `systemctl status` and `netstat`

## Requirements

- OS: Ubuntu/Debian
- Access: `root`
- Remote server reachable via SSH

## Quick Install (One Command)

Run on your Iranian server as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh)
```

If `curl` is unavailable:

```bash
wget -qO- https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh | bash
```

## Manual Usage

```bash
chmod +x setup_zapret2_tunnel.sh
sudo ./setup_zapret2_tunnel.sh
```

## What the script configures

- `zapret2` service
- `ssh-tunnel.service` at:
  - `/etc/systemd/system/ssh-tunnel.service`
- SSH local forwards in the form:
  - `-L 0.0.0.0:PORT:localhost:PORT`

## Security Notes

- The script briefly uses the remote root password only for `ssh-copy-id`.
- It unsets the password variable after key deployment.
- You should disable password login for SSH on the remote server after setup.

## Files

- `setup_zapret2_tunnel.sh` (main executable script)
- `scripts/setup_zapret2_tunnel.sh` (copy for structured repos)

## License

MIT
