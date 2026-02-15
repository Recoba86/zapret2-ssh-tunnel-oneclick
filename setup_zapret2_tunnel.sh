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

# ---------- Constants ----------
CONFIG_DIR="/etc/ssh-tunnel-manager"
TARGETS_FILE="${CONFIG_DIR}/targets.conf"
MANAGER_COMMAND="/usr/local/sbin/zapret2-tunnel"
ZAPRET_ARCHIVE_URL="https://h4.linklick.ir/b7d0be65a9a3ddfe3fa03008b69680fc/zapret2.tar.gz"
SELF_INSTALL_URL="https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh"
NFQUEUE_NUM="100"

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

pause_prompt() {
  read -r -p "Press Enter to continue... " _
}

ensure_root() {
  if [[ ${EUID} -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
  fi
}

ensure_storage() {
  mkdir -p "${CONFIG_DIR}"
  touch "${TARGETS_FILE}"
  chmod 700 "${CONFIG_DIR}"
  chmod 600 "${TARGETS_FILE}"
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

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local reply

  while true; do
    if [[ "${default}" == "y" ]]; then
      read -r -p "${prompt} [Y/n]: " reply
      reply="${reply:-y}"
    else
      read -r -p "${prompt} [y/N]: " reply
      reply="${reply:-n}"
    fi

    case "${reply}" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO)   return 1 ;;
      *) log_warn "Please answer y or n." ;;
    esac
  done
}

sanitize_name() {
  local raw="$1"
  local clean
  clean="$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  if [[ -z "${clean}" ]]; then
    clean="target-$(date +%s)"
  fi
  echo "${clean}"
}

target_exists() {
  local target_name="$1"
  awk -F'|' -v n="${target_name}" '$1 == n {found=1} END{exit !found}' "${TARGETS_FILE}"
}

service_name_for_target() {
  local target_name="$1"
  echo "ssh-tunnel-${target_name}.service"
}

ensure_packages() {
  local -a missing=()

  command -v sshpass >/dev/null 2>&1 || missing+=("sshpass")
  command -v curl >/dev/null 2>&1 || missing+=("curl")
  command -v wget >/dev/null 2>&1 || missing+=("wget")
  command -v netstat >/dev/null 2>&1 || missing+=("net-tools")

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_info "Installing missing packages: ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y "${missing[@]}"
  else
    log_success "All required packages are already installed."
  fi

  if ! command -v ssh-copy-id >/dev/null 2>&1; then
    log_info "Installing openssh-client (ssh-copy-id not found)..."
    apt-get install -y openssh-client
  fi
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

stop_disable_all_tunnel_units() {
  log_info "Stopping/disabling managed tunnel services..."

  systemctl stop ssh-tunnel.service 2>/dev/null || true
  systemctl disable ssh-tunnel.service 2>/dev/null || true

  shopt -s nullglob
  local unit_path
  for unit_path in /etc/systemd/system/ssh-tunnel-*.service; do
    local unit
    unit="$(basename "${unit_path}")"
    systemctl stop "${unit}" 2>/dev/null || true
    systemctl disable "${unit}" 2>/dev/null || true
  done
  shopt -u nullglob
}

remove_all_tunnel_unit_files() {
  log_info "Removing managed tunnel unit files..."
  rm -f /etc/systemd/system/ssh-tunnel.service

  shopt -s nullglob
  local unit_path
  for unit_path in /etc/systemd/system/ssh-tunnel-*.service; do
    rm -f "${unit_path}"
  done
  shopt -u nullglob

  systemctl daemon-reload
}

kill_existing_tunnel_processes() {
  log_info "Killing existing SSH tunnel processes..."
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
  wget "${ZAPRET_ARCHIVE_URL}" -O /root/zapret2.tar.gz

  log_info "Extracting zapret2 to root filesystem..."
  tar -xzvf /root/zapret2.tar.gz -C /

  systemctl daemon-reload
  systemctl enable zapret2.service
  systemctl restart zapret2.service

  log_success "zapret2 installed and started."
}

ensure_zapret2_running() {
  if systemctl list-unit-files | awk '{print $1}' | grep -qx 'zapret2.service'; then
    systemctl daemon-reload
    systemctl enable zapret2.service
    systemctl restart zapret2.service
    log_success "zapret2 service is active."
  else
    log_warn "zapret2 service not found. Installing..."
    install_zapret2
  fi
}

ensure_nfqueue_rule() {
  local ssh_port="$1"
  if iptables -C OUTPUT -p tcp --dport "${ssh_port}" -j NFQUEUE --queue-num "${NFQUEUE_NUM}" >/dev/null 2>&1; then
    log_success "NFQUEUE rule already exists for SSH port ${ssh_port}."
  else
    iptables -I OUTPUT -p tcp --dport "${ssh_port}" -j NFQUEUE --queue-num "${NFQUEUE_NUM}"
    log_success "NFQUEUE rule added for SSH port ${ssh_port}."
  fi
}

ssh_port_used_by_any_target() {
  local ssh_port="$1"
  awk -F'|' -v p="${ssh_port}" '$3 == p {found=1} END{exit !found}' "${TARGETS_FILE}"
}

remove_nfqueue_rule_if_unused() {
  local ssh_port="$1"
  if ssh_port_used_by_any_target "${ssh_port}"; then
    return 0
  fi

  while iptables -C OUTPUT -p tcp --dport "${ssh_port}" -j NFQUEUE --queue-num "${NFQUEUE_NUM}" >/dev/null 2>&1; do
    iptables -D OUTPUT -p tcp --dport "${ssh_port}" -j NFQUEUE --queue-num "${NFQUEUE_NUM}"
  done
  log_info "Removed unused NFQUEUE rule for SSH port ${ssh_port}."
}

ensure_root_ssh_key() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  if [[ ! -f /root/.ssh/id_ed25519 ]]; then
    log_info "Generating /root/.ssh/id_ed25519 (no passphrase)..."
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519
  else
    log_success "Existing SSH key found: /root/.ssh/id_ed25519"
  fi
}

copy_ssh_key() {
  local foreign_ip="$1"
  local foreign_ssh_port="$2"
  local foreign_pass="$3"

  sshpass -p "${foreign_pass}" ssh-copy-id \
    -i /root/.ssh/id_ed25519.pub \
    -p "${foreign_ssh_port}" \
    -o StrictHostKeyChecking=no \
    root@"${foreign_ip}"
}

port_in_use_by_other_target() {
  local query_port="$1"
  while IFS='|' read -r _name _ip _ssh_port csv_ports; do
    [[ -n "${_name}" ]] || continue
    local -a ports_arr=()
    IFS=',' read -r -a ports_arr <<<"${csv_ports}"
    local p
    for p in "${ports_arr[@]}"; do
      [[ "${p}" == "${query_port}" ]] && return 0
    done
  done < "${TARGETS_FILE}"
  return 1
}

build_forward_flags() {
  local csv_ports="$1"
  local -a ports_arr=()
  local flags=""
  local p

  IFS=',' read -r -a ports_arr <<<"${csv_ports}"
  for p in "${ports_arr[@]}"; do
    flags+="-L 0.0.0.0:${p}:localhost:${p} "
  done

  flags="${flags% }"
  echo "${flags}"
}

write_target_service() {
  local target_name="$1"
  local foreign_ip="$2"
  local foreign_ssh_port="$3"
  local csv_ports="$4"
  local unit_name
  local forward_flags

  unit_name="$(service_name_for_target "${target_name}")"
  forward_flags="$(build_forward_flags "${csv_ports}")"

  cat > "/etc/systemd/system/${unit_name}" <<UNIT
[Unit]
Description=Persistent SSH Tunnel (${target_name})
After=network-online.target zapret2.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -N -p ${foreign_ssh_port} -c aes128-gcm@openssh.com -o IPQoS=throughput -o TCPKeepAlive=yes -o PubkeyAuthentication=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 ${forward_flags} root@${foreign_ip}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable "${unit_name}"
  systemctl restart "${unit_name}"

  log_success "Service ${unit_name} is active."
}

append_target_config() {
  local target_name="$1"
  local foreign_ip="$2"
  local foreign_ssh_port="$3"
  local csv_ports="$4"

  echo "${target_name}|${foreign_ip}|${foreign_ssh_port}|${csv_ports}" >> "${TARGETS_FILE}"
}

prompt_target_details() {
  local default_name
  local raw_name

  while true; do
    default_name="target-$(($(wc -l < "${TARGETS_FILE}") + 1))"
    read -r -p "Enter target name [${default_name}]: " raw_name
    raw_name="${raw_name:-${default_name}}"
    TARGET_NAME="$(sanitize_name "${raw_name}")"

    if target_exists "${TARGET_NAME}"; then
      log_warn "Target name '${TARGET_NAME}' already exists. Use a different name."
      continue
    fi
    break
  done

  while true; do
    read -r -p "Enter Foreign Server IP: " TARGET_IP
    if validate_ipv4 "${TARGET_IP}"; then
      break
    fi
    log_warn "Invalid IPv4 address. Try again."
  done

  read -r -p "Enter Foreign Server SSH Port [22]: " TARGET_SSH_PORT
  TARGET_SSH_PORT="${TARGET_SSH_PORT:-22}"
  if ! validate_port "${TARGET_SSH_PORT}"; then
    log_error "Invalid SSH port: ${TARGET_SSH_PORT}"
    exit 1
  fi

  while true; do
    read -r -a TARGET_PORTS -p "Enter local ports for this target (space-separated, e.g. 3031 3032): "

    if [[ ${#TARGET_PORTS[@]} -eq 0 ]]; then
      log_warn "Please provide at least one port."
      continue
    fi

    local valid="yes"
    local -A seen=()
    local p
    local -a cleaned=()
    for p in "${TARGET_PORTS[@]}"; do
      if ! validate_port "${p}"; then
        log_warn "Invalid port detected: ${p}. Please re-enter all ports."
        valid="no"
        break
      fi
      if [[ -n "${seen["${p}"]+x}" ]]; then
        log_warn "Duplicate port in this target: ${p}. Please re-enter all ports."
        valid="no"
        break
      fi
      if port_in_use_by_other_target "${p}"; then
        log_warn "Port ${p} is already assigned to another target."
        valid="no"
        break
      fi
      seen["${p}"]=1
      cleaned+=("${p}")
    done

    if [[ "${valid}" == "yes" ]]; then
      TARGET_PORTS=("${cleaned[@]}")
      break
    fi
  done

  TARGET_PORTS_CSV="$(IFS=','; echo "${TARGET_PORTS[*]}")"
}

add_target_flow() {
  ensure_storage
  ensure_packages
  ensure_zapret2_running

  prompt_target_details
  ensure_root_ssh_key

  if prompt_yes_no "Run ssh-copy-id for ${TARGET_IP}:${TARGET_SSH_PORT} now?" "y"; then
    local target_pass
    while true; do
      read -r -s -p "Enter Foreign Server Root Password: " target_pass
      echo
      [[ -n "${target_pass}" ]] && break
      log_warn "Password cannot be empty."
    done

    log_info "Copying SSH key to remote server..."
    copy_ssh_key "${TARGET_IP}" "${TARGET_SSH_PORT}" "${target_pass}"
    unset target_pass
    log_success "Passwordless SSH login configured for ${TARGET_NAME}."
  else
    log_warn "Skipped ssh-copy-id. Make sure key-based auth is already configured."
  fi

  append_target_config "${TARGET_NAME}" "${TARGET_IP}" "${TARGET_SSH_PORT}" "${TARGET_PORTS_CSV}"
  ensure_nfqueue_rule "${TARGET_SSH_PORT}"
  write_target_service "${TARGET_NAME}" "${TARGET_IP}" "${TARGET_SSH_PORT}" "${TARGET_PORTS_CSV}"

  log_success "Target '${TARGET_NAME}' added with ports: ${TARGET_PORTS[*]}"
}

initial_setup_flow() {
  log_warn "Initial setup will flush iptables and recreate all managed tunnel services."
  if ! prompt_yes_no "Continue with initial setup?" "n"; then
    log_info "Initial setup canceled."
    return 0
  fi

  ensure_storage
  ensure_packages
  reset_iptables

  systemctl stop zapret2.service 2>/dev/null || true
  systemctl disable zapret2.service 2>/dev/null || true

  stop_disable_all_tunnel_units
  remove_all_tunnel_unit_files
  kill_existing_tunnel_processes

  : > "${TARGETS_FILE}"

  install_zapret2
  add_target_flow
  install_manager_command

  log_success "Initial setup completed."
}

list_targets() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnel targets configured yet."
    return 0
  fi

  printf "\n${C_BOLD}Configured Tunnel Targets${C_RESET}\n"
  printf "%-4s %-20s %-17s %-9s %s\n" "#" "NAME" "FOREIGN_IP" "SSH_PORT" "PORTS"
  printf "%-4s %-20s %-17s %-9s %s\n" "--" "--------------------" "-----------------" "---------" "----------------"

  local idx=0
  while IFS='|' read -r name ip ssh_port ports_csv; do
    [[ -n "${name}" ]] || continue
    idx=$((idx + 1))
    printf "%-4s %-20s %-17s %-9s %s\n" "${idx}" "${name}" "${ip}" "${ssh_port}" "${ports_csv//,/ }"
  done < "${TARGETS_FILE}"
  echo
}

remove_target_flow() {
  ensure_storage

  local -a names=()
  local -a ssh_ports=()

  while IFS='|' read -r name _ip ssh_port _ports_csv; do
    [[ -n "${name}" ]] || continue
    names+=("${name}")
    ssh_ports+=("${ssh_port}")
  done < "${TARGETS_FILE}"

  if [[ ${#names[@]} -eq 0 ]]; then
    log_warn "No targets to remove."
    return 0
  fi

  list_targets

  local choice
  while true; do
    read -r -p "Enter target number to remove: " choice
    if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#names[@]} )); then
      break
    fi
    log_warn "Invalid selection."
  done

  local idx=$((choice - 1))
  local target_name="${names[${idx}]}"
  local target_ssh_port="${ssh_ports[${idx}]}"
  local unit_name
  unit_name="$(service_name_for_target "${target_name}")"

  systemctl stop "${unit_name}" 2>/dev/null || true
  systemctl disable "${unit_name}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${unit_name}"

  awk -F'|' -v n="${target_name}" '$1 != n' "${TARGETS_FILE}" > "${TARGETS_FILE}.tmp"
  mv "${TARGETS_FILE}.tmp" "${TARGETS_FILE}"

  systemctl daemon-reload
  remove_nfqueue_rule_if_unused "${target_ssh_port}"

  log_success "Target '${target_name}' removed."
}

restart_all_tunnels() {
  ensure_storage
  ensure_zapret2_running

  local restarted=0
  while IFS='|' read -r name _ip ssh_port ports_csv; do
    [[ -n "${name}" ]] || continue
    ensure_nfqueue_rule "${ssh_port}"
    write_target_service "${name}" "${_ip}" "${ssh_port}" "${ports_csv}"
    restarted=$((restarted + 1))
  done < "${TARGETS_FILE}"

  if (( restarted == 0 )); then
    log_warn "No configured targets found."
  else
    log_success "Restarted/reloaded ${restarted} tunnel target(s)."
  fi
}

status_flow() {
  ensure_storage

  log_info "Service status: zapret2"
  systemctl --no-pager --full status zapret2.service || true

  local units_found=0
  while IFS='|' read -r name _ip _ssh_port _ports_csv; do
    [[ -n "${name}" ]] || continue
    units_found=$((units_found + 1))
    local unit_name
    unit_name="$(service_name_for_target "${name}")"
    log_info "Service status: ${unit_name}"
    systemctl --no-pager --full status "${unit_name}" || true
  done < "${TARGETS_FILE}"

  if (( units_found == 0 )); then
    log_warn "No tunnel services configured."
  fi

  if ! command -v netstat >/dev/null 2>&1; then
    log_warn "netstat not found. Install net-tools to check listening ports."
    return 0
  fi

  local -a all_ports=()
  while IFS='|' read -r _name _ip _ssh_port csv_ports; do
    [[ -n "${_name}" ]] || continue
    local -a tmp_ports=()
    IFS=',' read -r -a tmp_ports <<<"${csv_ports}"
    local p
    for p in "${tmp_ports[@]}"; do
      all_ports+=("${p}")
    done
  done < "${TARGETS_FILE}"

  if [[ ${#all_ports[@]} -eq 0 ]]; then
    log_warn "No ports configured yet."
    return 0
  fi

  local pattern
  pattern="$(printf ':%s|' "${all_ports[@]}")"
  pattern="${pattern%|}"

  log_info "Listening port check via netstat..."
  if netstat -tunlp | grep -E "${pattern}"; then
    log_success "Configured tunnel ports are listening."
  else
    log_warn "No listening sockets found for configured ports."
  fi
}

install_manager_command() {
  log_info "Installing management command at ${MANAGER_COMMAND} ..."
  local current_source="${BASH_SOURCE[0]}"

  if [[ -f "${current_source}" && "${current_source}" != /dev/fd/* ]]; then
    install -m 0755 "${current_source}" "${MANAGER_COMMAND}"
    log_success "Command installed. Run: ${MANAGER_COMMAND}"
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${SELF_INSTALL_URL}" -o "${MANAGER_COMMAND}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${MANAGER_COMMAND}" "${SELF_INSTALL_URL}"
  else
    log_error "Could not install manager command: neither curl nor wget is available."
    return 1
  fi

  chmod 0755 "${MANAGER_COMMAND}"
  log_success "Command installed. Run: ${MANAGER_COMMAND}"
}

show_main_menu() {
  echo
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo -e "${C_BOLD} Zapret2 + Multi-Target SSH Tunnel Manager    ${C_RESET}"
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo "1) Initial setup (fresh install/reset + add first target)"
  echo "2) Add new tunnel target (server/ports)"
  echo "3) List configured targets"
  echo "4) Remove a target"
  echo "5) Restart/rebuild all tunnel services"
  echo "6) Show service status + listening ports"
  echo "7) Install/update management command (${MANAGER_COMMAND})"
  echo "0) Exit"
}

run_menu() {
  while true; do
    show_main_menu
    read -r -p "Select an option: " menu_choice

    case "${menu_choice}" in
      1)
        initial_setup_flow
        pause_prompt
        ;;
      2)
        add_target_flow
        pause_prompt
        ;;
      3)
        list_targets
        pause_prompt
        ;;
      4)
        remove_target_flow
        pause_prompt
        ;;
      5)
        restart_all_tunnels
        pause_prompt
        ;;
      6)
        status_flow
        pause_prompt
        ;;
      7)
        install_manager_command
        pause_prompt
        ;;
      0)
        log_info "Goodbye."
        exit 0
        ;;
      *)
        log_warn "Invalid option."
        ;;
    esac
  done
}

show_help() {
  cat <<HELP
Usage: $(basename "$0") [option]

Options:
  --menu             Open interactive menu (default)
  --initial-setup    Run initial setup flow directly
  --add-target       Add a new tunnel target directly
  --status           Show service status and listening ports
  --install-command  Install/update ${MANAGER_COMMAND}
  -h, --help         Show this help
HELP
}

main() {
  ensure_root
  require_cmd systemctl
  require_cmd iptables
  require_cmd apt-get
  require_cmd awk
  require_cmd sed
  require_cmd tr

  ensure_storage

  case "${1:---menu}" in
    --menu)
      run_menu
      ;;
    --initial-setup)
      initial_setup_flow
      ;;
    --add-target)
      add_target_flow
      ;;
    --status)
      status_flow
      ;;
    --install-command)
      install_manager_command
      ;;
    -h|--help)
      show_help
      ;;
    *)
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
}

main "$@"
