#!/usr/bin/env bash
set -Eeuo pipefail

# ---------- Colors ----------
if [[ -t 1 ]]; then
  C_RESET='\033[0m'
  C_RED='\033[0;31m'
  C_GREEN='\033[0;32m'
  C_YELLOW='\033[1;33m'
  C_BLUE='\033[0;34m'
  C_BOLD='\033[1m'
else
  C_RESET=''
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_BOLD=''
fi

log_info()    { echo -e "${C_BLUE}[INFO]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
log_error()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }

on_error() {
  local exit_code=$?
  log_error "Command failed (exit ${exit_code}) at line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  exit "${exit_code}"
}
trap on_error ERR

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log_error "Required command not found: ${cmd}"
    exit 1
  fi
}

validate_ipv4() {
  local ip="$1"
  local IFS='.'
  local -a octets
  read -r -a octets <<<"${ip}"
  [[ ${#octets[@]} -eq 4 ]] || return 1

  local oct
  for oct in "${octets[@]}"; do
    [[ "${oct}" =~ ^[0-9]{1,3}$ ]] || return 1
    (( oct >= 0 && oct <= 255 )) || return 1
  done
}

validate_port() {
  local port="$1"
  [[ "${port}" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 ))
}

prompt_inputs() {
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo -e "${C_BOLD} Zapret2 + Obfuscated SSH Tunnel Setup Wizard ${C_RESET}"
  echo -e "${C_BOLD}==============================================${C_RESET}"

  while true; do
    read -r -p "Enter Foreign Server IP: " FOREIGN_IP
    if validate_ipv4 "${FOREIGN_IP}"; then
      break
    fi
    log_warn "Invalid IPv4 address. Try again."
  done

  read -r -p "Enter Foreign Server SSH Port [22]: " FOREIGN_SSH_PORT
  FOREIGN_SSH_PORT="${FOREIGN_SSH_PORT:-22}"
  if ! validate_port "${FOREIGN_SSH_PORT}"; then
    log_error "Invalid SSH port: ${FOREIGN_SSH_PORT}"
    exit 1
  fi

  while true; do
    read -r -s -p "Enter Foreign Server Root Password: " FOREIGN_PASS
    echo
    [[ -n "${FOREIGN_PASS}" ]] && break
    log_warn "Password cannot be empty."
  done

  while true; do
    read -r -a FORWARD_PORTS -p "Enter local/remote ports to forward (space-separated, e.g. 3031 3032 4000): "

    if [[ ${#FORWARD_PORTS[@]} -eq 0 ]]; then
      log_warn "Please provide at least one port."
      continue
    fi

    local p
    local -A seen=()
    local -a cleaned=()
    for p in "${FORWARD_PORTS[@]}"; do
      if ! validate_port "${p}"; then
        log_warn "Invalid port detected: ${p}. Please re-enter all ports."
        cleaned=()
        break
      fi
      if [[ -z "${seen["${p}"]+x}" ]]; then
        seen["${p}"]=1
        cleaned+=("${p}")
      fi
    done

    if [[ ${#cleaned[@]} -gt 0 ]]; then
      FORWARD_PORTS=("${cleaned[@]}")
      break
    fi
  done

  log_success "Input collection complete."
}

install_packages() {
  log_info "Updating APT cache..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y

  log_info "Installing required packages: sshpass curl wget net-tools"
  apt-get install -y sshpass curl wget net-tools

  if ! command -v ssh-copy-id >/dev/null 2>&1; then
    log_info "Installing openssh-client (ssh-copy-id not found)..."
    apt-get install -y openssh-client
  fi

  log_success "Package installation completed."
}

reset_iptables() {
  log_info "Resetting iptables rules (filter, nat, mangle) and setting policies to ACCEPT..."
  local table
  for table in filter nat mangle; do
    iptables -t "${table}" -F || true
    iptables -t "${table}" -X || true
  done

  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  log_success "iptables cleanup completed."
}

stop_existing_services_and_tunnels() {
  log_info "Stopping/disabling existing services: zapret2, ssh-tunnel"
  local svc
  for svc in zapret2 ssh-tunnel; do
    systemctl stop "${svc}.service" 2>/dev/null || true
    systemctl disable "${svc}.service" 2>/dev/null || true
  done

  log_info "Killing existing SSH tunnel processes..."
  # Only kill tunnel-like SSH commands that include local forwards.
  local pids
  pids="$(pgrep -f 'ssh .* -N .* -L 0\.0\.0\.0:' || true)"
  if [[ -n "${pids}" ]]; then
    kill ${pids} || true
    sleep 1
    pids="$(pgrep -f 'ssh .* -N .* -L 0\.0\.0\.0:' || true)"
    [[ -z "${pids}" ]] || kill -9 ${pids} || true
    log_success "Existing SSH tunnel processes terminated."
  else
    log_success "No existing SSH tunnel processes found."
  fi
}

install_zapret2() {
  log_info "Downloading zapret2 archive..."
  wget "https://h4.linklick.ir/b7d0be65a9a3ddfe3fa03008b69680fc/zapret2.tar.gz" -O /root/zapret2.tar.gz

  log_info "Extracting zapret2 to root filesystem..."
  tar -xzvf /root/zapret2.tar.gz -C /

  log_info "Reloading systemd and enabling zapret2 service..."
  systemctl daemon-reload
  systemctl enable zapret2.service
  systemctl restart zapret2.service

  log_info "Adding NFQUEUE iptables rule for SSH obfuscation traffic..."
  iptables -I OUTPUT -p tcp --dport "${FOREIGN_SSH_PORT}" -j NFQUEUE --queue-num 100

  log_success "zapret2 installed and configured."
}

setup_passwordless_ssh() {
  log_info "Preparing SSH key for root..."
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  if [[ ! -f /root/.ssh/id_ed25519 ]]; then
    log_info "Generating /root/.ssh/id_ed25519 (no passphrase)..."
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
  else
    log_success "Existing SSH key found: /root/.ssh/id_ed25519"
  fi

  log_info "Copying SSH key to foreign server with sshpass..."
  sshpass -p "${FOREIGN_PASS}" ssh-copy-id \
    -i /root/.ssh/id_ed25519.pub \
    -p "${FOREIGN_SSH_PORT}" \
    -o StrictHostKeyChecking=no \
    root@"${FOREIGN_IP}"

  unset FOREIGN_PASS
  log_success "Passwordless SSH login configured."
}

build_forward_string() {
  DYNAMIC_PORTS_STRING=""
  local port
  for port in "${FORWARD_PORTS[@]}"; do
    DYNAMIC_PORTS_STRING+="-L 0.0.0.0:${port}:localhost:${port} "
  done
  DYNAMIC_PORTS_STRING="${DYNAMIC_PORTS_STRING% }"
}

create_tunnel_service() {
  build_forward_string

  log_info "Creating /etc/systemd/system/ssh-tunnel.service ..."
  cat > /etc/systemd/system/ssh-tunnel.service <<UNIT
[Unit]
Description=Persistent SSH Local Port Forward Tunnel
After=network-online.target zapret2.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -N -p ${FOREIGN_SSH_PORT} -c aes128-gcm@openssh.com -o IPQoS=throughput -o TCPKeepAlive=yes -o PubkeyAuthentication=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 ${DYNAMIC_PORTS_STRING} root@${FOREIGN_IP}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

  log_info "Reloading systemd and starting ssh-tunnel service..."
  systemctl daemon-reload
  systemctl enable ssh-tunnel.service
  systemctl restart ssh-tunnel.service

  log_success "ssh-tunnel.service created and started."
}

verify_setup() {
  log_info "Service status: zapret2"
  systemctl --no-pager --full status zapret2.service || true

  log_info "Service status: ssh-tunnel"
  systemctl --no-pager --full status ssh-tunnel.service || true

  local pattern
  pattern="$(printf ':%s|' "${FORWARD_PORTS[@]}")"
  pattern="${pattern%|}"

  log_info "Listening port check (netstat) for forwarded ports: ${FORWARD_PORTS[*]}"
  if netstat -tunlp | grep -E "${pattern}"; then
    log_success "Forwarded ports are listening."
  else
    log_warn "No listening sockets found for requested ports. Check ssh-tunnel logs: journalctl -u ssh-tunnel -n 100"
  fi
}

main() {
  require_cmd systemctl
  require_cmd iptables
  require_cmd apt-get

  if [[ ${EUID} -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
  fi

  prompt_inputs
  install_packages
  reset_iptables
  stop_existing_services_and_tunnels
  install_zapret2
  setup_passwordless_ssh
  create_tunnel_service
  verify_setup

  echo
  log_success "All steps completed successfully."
  echo -e "${C_BOLD}Foreign Server:${C_RESET} ${FOREIGN_IP}:${FOREIGN_SSH_PORT}"
  echo -e "${C_BOLD}Forwarded Ports:${C_RESET} ${FORWARD_PORTS[*]}"
}

main "$@"
