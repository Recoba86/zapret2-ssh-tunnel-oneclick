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
  C_DIM='\033[2m'
else
  C_RESET=''
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_BOLD=''
  C_DIM=''
fi

log_info()    { echo -e "${C_BLUE}[INFO]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
log_warn()    { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
log_error()   { echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2; }

# ---------- Constants ----------
CONFIG_DIR="/etc/ssh-tunnel-manager"
TARGETS_FILE="${CONFIG_DIR}/targets.conf"
PROFILE_META_FILE="${CONFIG_DIR}/zapret2_profile"
MANAGER_COMMAND="/usr/local/sbin/zapret2-tunnel"
ZAPRET_ARCHIVE_URL="https://h4.linklick.ir/b7d0be65a9a3ddfe3fa03008b69680fc/zapret2.tar.gz"
SELF_INSTALL_URL="https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main/setup_zapret2_tunnel.sh"
PROFILES_BASE_URL="https://raw.githubusercontent.com/Recoba86/zapret2-ssh-tunnel-oneclick/main"
PROFILES_FALLBACK_BASE_URL="https://cdn.jsdelivr.net/gh/Recoba86/zapret2-ssh-tunnel-oneclick@main"
NFQUEUE_NUM="100"

# targets.conf format (new):
#   key|label|foreign_ip|foreign_ssh_port|bind_addr|ports_csv
# Backward compatible (old):
#   key|foreign_ip|foreign_ssh_port|ports_csv

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

install_file() {
  # Portable-ish file install helper: prefers `install`, falls back to cp+chmod.
  local mode="$1"
  local src="$2"
  local dest="$3"

  if command -v install >/dev/null 2>&1; then
    install -m "${mode}" "${src}" "${dest}"
    return 0
  fi

  cp -f "${src}" "${dest}"
  chmod "${mode}" "${dest}"
}

typed_confirm() {
  # Require an exact confirmation token to proceed with destructive actions.
  local token="$1"
  local prompt="$2"
  local input=""

  echo
  echo -e "${C_YELLOW}${prompt}${C_RESET}"
  read -r -p "Type '${token}' to confirm: " input
  [[ "${input}" == "${token}" ]]
}

iptables_remove_nfqueue_queue100_output() {
  # Removes OUTPUT-chain rules that match our NFQUEUE usage (tcp dport -> queue 100).
  # This avoids flushing the entire firewall on uninstall.
  if ! command -v iptables >/dev/null 2>&1; then
    return 0
  fi

  local line
  while IFS= read -r line; do
    # Example:
    #   -A OUTPUT -p tcp -m tcp --dport 22 -j NFQUEUE --queue-num 100
    if [[ "${line}" == -A\ OUTPUT* ]] && [[ "${line}" == *"-p tcp"* ]] && [[ "${line}" == *"--dport "* ]] && [[ "${line}" == *"-j NFQUEUE"* ]] && [[ "${line}" == *"--queue-num ${NFQUEUE_NUM}"* ]]; then
      local del
      del="${line/-A OUTPUT/-D OUTPUT}"
      # shellcheck disable=SC2086
      iptables ${del} >/dev/null 2>&1 || true
    fi
  done < <(iptables -S OUTPUT 2>/dev/null || true)
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
  touch "${PROFILE_META_FILE}"
  chmod 700 "${CONFIG_DIR}"
  chmod 600 "${TARGETS_FILE}"
  chmod 600 "${PROFILE_META_FILE}"
}

trim() {
  # Trim leading/trailing whitespace
  echo "$1" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
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

validate_bind_addr() {
  local addr="$1"
  [[ "${addr}" == "127.0.0.1" || "${addr}" == "0.0.0.0" ]]
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

sanitize_key() {
  local raw="$1"
  local clean
  clean="$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  if [[ -z "${clean}" ]]; then
    clean="target-$(date +%s)"
  fi
  echo "${clean}"
}

target_exists() {
  local target_key="$1"
  awk -F'|' -v n="${target_key}" '$1 == n {found=1} END{exit !found}' "${TARGETS_FILE}"
}

service_name_for_target() {
  local target_key="$1"
  echo "ssh-tunnel-${target_key}.service"
}

read_target_line() {
  # Input: a single line (pipe-separated). Output: key|label|ip|ssh_port|bind_addr|ports_csv
  local line="$1"
  local f1 f2 f3 f4 f5 f6
  IFS='|' read -r f1 f2 f3 f4 f5 f6 <<<"${line}"

  # v2 format: key|label|ip|ssh_port|bind_addr|ports_csv
  if [[ -n "${f6}" ]]; then
    local bind="${f5}"
    if ! validate_bind_addr "${bind}"; then
      bind="0.0.0.0"
    fi
    echo "${f1}|${f2}|${f3}|${f4}|${bind}|${f6}"
    return 0
  fi

  # v1 format: key|label|ip|ssh_port|ports_csv
  if [[ -n "${f5}" ]]; then
    echo "${f1}|${f2}|${f3}|${f4}|0.0.0.0|${f5}"
  else
    # old format: key|ip|ssh_port|ports_csv
    echo "${f1}|${f1}|${f2}|${f3}|0.0.0.0|${f4}"
  fi
}

script_dir() {
  # Best-effort directory resolution (may be /dev/fd/* when run via process substitution).
  local src="${BASH_SOURCE[0]}"
  if [[ "${src}" == /dev/fd/* ]]; then
    echo ""
    return 0
  fi
  (cd -- "$(dirname -- "${src}")" && pwd)
}

download_to_file() {
  local url="$1"
  local dest="$2"

  local tmp
  tmp="$(mktemp)"

  if command -v curl >/dev/null 2>&1; then
    if curl -fSL --connect-timeout 10 --max-time 45 -sS "${url}" -o "${tmp}"; then
      if [[ -s "${tmp}" ]]; then
        mv -f "${tmp}" "${dest}"
        return 0
      fi
    fi
    rm -f "${tmp}"
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    if wget -qO "${tmp}" "${url}"; then
      if [[ -s "${tmp}" ]]; then
        mv -f "${tmp}" "${dest}"
        return 0
      fi
    fi
    rm -f "${tmp}"
    return 1
  fi

  log_error "Neither curl nor wget is available to download ${url}"
  rm -f "${tmp}" 2>/dev/null || true
  return 1
}

backup_file_if_exists() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    cp -a "${path}" "${path}.bak.${ts}"
  fi
}

current_profile_name() {
  if [[ -s "${PROFILE_META_FILE}" ]]; then
    cat "${PROFILE_META_FILE}" | head -n 1
  elif [[ -f /etc/zapret2.lua ]]; then
    echo "custom"
  else
    echo "unknown"
  fi
}

profile_filename_for_choice() {
  local choice="$1"
  case "${choice}" in
    1) echo "fake.lua" ;;
    2) echo "split.lua" ;;
    3) echo "disorder.lua" ;;
    *) return 1 ;;
  esac
}

download_profile_file() {
  # Tries repo root first, then /scripts/ (to match common layouts).
  local filename="$1"
  local dest="$2"

  local -a bases=("${PROFILES_BASE_URL}" "${PROFILES_FALLBACK_BASE_URL}")
  local base
  for base in "${bases[@]}"; do
    local url_root="${base}/${filename}"
    local url_scripts="${base}/scripts/${filename}"

    if download_to_file "${url_root}" "${dest}"; then
      log_success "Downloaded profile from: ${url_root}"
      return 0
    fi
    if download_to_file "${url_scripts}" "${dest}"; then
      log_success "Downloaded profile from: ${url_scripts}"
      return 0
    fi
  done

  log_error "Failed to download profile '${filename}'."
  log_error "Tried: ${PROFILES_BASE_URL}/${filename}"
  log_error "Tried: ${PROFILES_BASE_URL}/scripts/${filename}"
  log_error "Tried: ${PROFILES_FALLBACK_BASE_URL}/${filename}"
  log_error "Tried: ${PROFILES_FALLBACK_BASE_URL}/scripts/${filename}"
  return 1
}

apply_zapret2_profile() {
  # Generic profile switching: copy a repo-hosted (or local) file to /etc/zapret2.lua and restart zapret2.
  local choice="$1"
  local filename
  filename="$(profile_filename_for_choice "${choice}")"

  # Ensure tooling and service exist before applying.
  ensure_packages
  ensure_zapret2_running

  local label
  case "${choice}" in
    1) label="Profile 1" ;;
    2) label="Profile 2" ;;
    3) label="Profile 3" ;;
  esac

  local tmp
  tmp="$(mktemp)"

  local src_dir
  src_dir="$(script_dir)"

  log_info "Applying Zapret2 ${label} (${filename}) ..."

  if [[ -n "${src_dir}" && -f "${src_dir}/${filename}" ]]; then
    log_info "Using local profile file: ${src_dir}/${filename}"
    cp -f "${src_dir}/${filename}" "${tmp}"
  elif [[ -n "${src_dir}" && -f "${src_dir}/scripts/${filename}" ]]; then
    log_info "Using local profile file: ${src_dir}/scripts/${filename}"
    cp -f "${src_dir}/scripts/${filename}" "${tmp}"
  else
    log_info "Downloading profile (${filename}) from repository raw files..."
    download_profile_file "${filename}" "${tmp}"
  fi

  if [[ ! -s "${tmp}" ]]; then
    rm -f "${tmp}"
    log_error "Downloaded/copied profile is empty: ${filename}"
    return 1
  fi

  backup_file_if_exists "/etc/zapret2.lua"
  install_file 0644 "${tmp}" /etc/zapret2.lua
  rm -f "${tmp}"

  systemctl restart zapret2.service

  if systemctl is-active --quiet zapret2.service; then
    echo "${label} (${filename})" > "${PROFILE_META_FILE}"
    log_success "Zapret2 restarted. Active profile: ${label} (${filename})"
  else
    log_warn "zapret2.service is not active after restart. Check: systemctl status zapret2.service"
  fi
}

select_and_apply_profile_menu() {
  ensure_storage
  ensure_packages

  local current
  current="$(current_profile_name)"

  echo
  echo -e "${C_BOLD}Zapret2 Profile Selection${C_RESET}"
  echo -e "Current: ${C_DIM}${current}${C_RESET}"
  echo "1) Profile 1 (fake.lua)"
  echo "2) Profile 2 (split.lua)"
  echo "3) Profile 3 (disorder.lua)"
  echo "0) Skip (keep current /etc/zapret2.lua)"

  local choice
  while true; do
    read -r -p "Select a profile: " choice
    case "${choice}" in
      0) log_info "Skipped profile change."; return 0 ;;
      1|2|3) apply_zapret2_profile "${choice}"; return 0 ;;
      *) log_warn "Invalid option. Choose 0-3." ;;
    esac
  done
}

prompt_bind_address() {
  # Default to public bind (0.0.0.0) so remote clients can connect, but warn users.
  local default="${1:-0.0.0.0}"
  local choice

  echo
  echo -e "${C_BOLD}Bind Address For Local Forwards${C_RESET}"
  echo "1) 127.0.0.1  (Recommended: only local access)"
  echo "2) 0.0.0.0    (Public: listen on all interfaces)"
  echo -e "${C_YELLOW}Note:${C_RESET} If you choose 0.0.0.0, make sure your firewall restricts access to these ports."

  while true; do
    if [[ "${default}" == "0.0.0.0" ]]; then
      read -r -p "Select [1-2] (default 2): " choice
      choice="${choice:-2}"
    else
      read -r -p "Select [1-2] (default 1): " choice
      choice="${choice:-1}"
    fi

    case "${choice}" in
      1) echo "127.0.0.1"; return 0 ;;
      2) echo "0.0.0.0"; return 0 ;;
      *) log_warn "Invalid selection." ;;
    esac
  done
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

uninstall_flow() {
  ensure_storage

  log_warn "Uninstall will remove tunnel services, manager config, and optionally zapret2 config/service."
  if ! typed_confirm "UNINSTALL-ALL" "This action is destructive and intended to fully clean this setup."; then
    log_info "Uninstall canceled."
    return 0
  fi

  if prompt_yes_no "Remove NFQUEUE iptables rules added by this manager (queue ${NFQUEUE_NUM})?" "y"; then
    log_info "Removing NFQUEUE iptables rules from OUTPUT chain..."
    iptables_remove_nfqueue_queue100_output
    log_success "NFQUEUE iptables cleanup completed."
  else
    log_info "Skipping iptables changes."
  fi

  log_info "Stopping/disabling tunnel services..."
  stop_disable_all_tunnel_units
  remove_all_tunnel_unit_files
  kill_existing_tunnel_processes

  if prompt_yes_no "Stop/disable zapret2.service and remove /etc/zapret2.lua?" "y"; then
    systemctl stop zapret2.service 2>/dev/null || true
    systemctl disable zapret2.service 2>/dev/null || true

    if [[ -f /etc/zapret2.lua ]]; then
      backup_file_if_exists "/etc/zapret2.lua"
      rm -f /etc/zapret2.lua
    fi

    # Best-effort: remove the zapret2 unit file if it exists as a standalone unit.
    local frag
    frag="$(systemctl show -p FragmentPath --value zapret2.service 2>/dev/null || true)"
    if [[ -n "${frag}" && -f "${frag}" ]]; then
      rm -f "${frag}"
    fi

    systemctl daemon-reload
    log_success "zapret2 service/config cleanup completed."
  else
    log_info "Skipping zapret2 removal."
  fi

  log_info "Removing manager command and configuration..."
  rm -f "${MANAGER_COMMAND}" 2>/dev/null || true
  rm -rf "${CONFIG_DIR}" 2>/dev/null || true
  rm -f /root/zapret2.tar.gz 2>/dev/null || true

  log_success "Uninstall completed. System should be clean."
}

ensure_unit_present_for_selected() {
  # If the systemd unit file is missing (e.g. deleted manually), rebuild it from config.
  local idx="$1"
  local key="${T_KEYS[${idx}]}"
  local ip="${T_IPS[${idx}]}"
  local ssh_port="${T_SSH_PORTS[${idx}]}"
  local bind="${T_BINDS[${idx}]}"
  local ports_csv="${T_PORTS_CSV[${idx}]}"

  local unit
  unit="$(service_name_for_target "${key}")"

  if [[ -f "/etc/systemd/system/${unit}" ]]; then
    return 0
  fi

  log_warn "Unit file missing for ${unit}. Rebuilding from stored config..."
  write_target_service "${key}" "${ip}" "${ssh_port}" "${bind}" "${ports_csv}"
}

tunnel_power_flow() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnels configured yet."
    return 0
  fi

  if ! select_target_index; then
    log_info "Canceled."
    return 0
  fi

  local idx="${SELECTED_IDX}"
  local key="${T_KEYS[${idx}]}"
  local label="${T_LABELS[${idx}]}"
  local unit
  unit="$(service_name_for_target "${key}")"

  while true; do
    local active enabled
    active="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"

    echo
    echo -e "${C_BOLD}Tunnel Power Control${C_RESET}"
    echo "Tunnel: ${label} (${unit})"
    echo "State:  active=${active}, enabled=${enabled}"
    echo
    echo "1) Stop (temporary off)"
    echo "2) Start (temporary on)"
    echo "3) Disable + Stop (off at boot)"
    echo "4) Enable + Start (on at boot)"
    echo "0) Back"

    local choice
    read -r -p "Select an option: " choice

    case "${choice}" in
      1)
        systemctl stop "${unit}" 2>/dev/null || true
        log_success "Stopped: ${label}"
        ;;
      2)
        ensure_unit_present_for_selected "${idx}"
        systemctl start "${unit}" 2>/dev/null || true
        log_success "Started: ${label}"
        ;;
      3)
        systemctl disable --now "${unit}" 2>/dev/null || true
        log_success "Disabled + stopped: ${label}"
        ;;
      4)
        ensure_unit_present_for_selected "${idx}"
        systemctl enable --now "${unit}" 2>/dev/null || true
        log_success "Enabled + started: ${label}"
        ;;
      0)
        return 0
        ;;
      *)
        log_warn "Invalid option."
        ;;
    esac
  done
}

kill_existing_tunnel_processes() {
  log_info "Killing existing SSH tunnel processes..."
  local pids
  # Match typical local-forward tunnels (bind address can vary).
  pids="$(pgrep -f 'ssh .* -N .* -L [0-9.]+:[0-9]+:localhost:' || true)"
  if [[ -n "${pids}" ]]; then
    kill ${pids} || true
    sleep 1
    pids="$(pgrep -f 'ssh .* -N .* -L [0-9.]+:[0-9]+:localhost:' || true)"
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
    return 0
  fi
  iptables -I OUTPUT -p tcp --dport "${ssh_port}" -j NFQUEUE --queue-num "${NFQUEUE_NUM}"
}

ssh_port_used_by_any_target() {
  local ssh_port="$1"
  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    local parsed
    parsed="$(read_target_line "${line}")"
    local _key _label _ip _ssh_port _bind _ports
    IFS='|' read -r _key _label _ip _ssh_port _bind _ports <<<"${parsed}"
    [[ "${_ssh_port}" == "${ssh_port}" ]] && return 0
  done < "${TARGETS_FILE}"
  return 1
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
  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    local parsed
    parsed="$(read_target_line "${line}")"
    local _key _label _ip _ssh_port _bind ports_csv
    IFS='|' read -r _key _label _ip _ssh_port _bind ports_csv <<<"${parsed}"

    local -a ports_arr=()
    IFS=',' read -r -a ports_arr <<<"${ports_csv}"
    local p
    for p in "${ports_arr[@]}"; do
      [[ "${p}" == "${query_port}" ]] && return 0
    done
  done < "${TARGETS_FILE}"

  return 1
}

port_in_use_by_other_target_excluding() {
  local exclude_key="$1"
  local query_port="$2"
  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    local parsed
    parsed="$(read_target_line "${line}")"
    local _key _label _ip _ssh_port _bind ports_csv
    IFS='|' read -r _key _label _ip _ssh_port _bind ports_csv <<<"${parsed}"

    [[ "${_key}" == "${exclude_key}" ]] && continue

    local -a ports_arr=()
    IFS=',' read -r -a ports_arr <<<"${ports_csv}"
    local p
    for p in "${ports_arr[@]}"; do
      [[ "${p}" == "${query_port}" ]] && return 0
    done
  done < "${TARGETS_FILE}"

  return 1
}

replace_target_line_in_config() {
  # Replace the line matching key with a fully specified v2 line.
  local old_key="$1"
  local new_line="$2"

  awk -F'|' -v k="${old_key}" -v nl="${new_line}" 'BEGIN{OFS="|"} $1==k {$0=nl} {print}' "${TARGETS_FILE}" > "${TARGETS_FILE}.tmp"
  mv "${TARGETS_FILE}.tmp" "${TARGETS_FILE}"
}

select_target_index() {
  # Populates arrays and returns selected index in SELECTED_IDX.
  ensure_storage
  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnels configured yet."
    return 1
  fi

  list_targets_basic
  collect_targets_arrays

  local choice
  while true; do
    read -r -p "Select a tunnel number (0 to cancel): " choice
    if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice == 0 )); then
      return 1
    fi
    if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#T_KEYS[@]} )); then
      SELECTED_IDX=$((choice - 1))
      return 0
    fi
    log_warn "Invalid selection."
  done
}

build_forward_flags() {
  local bind_addr="$1"
  local ports_csv="$2"
  local -a ports_arr=()
  local flags=""
  local p

  IFS=',' read -r -a ports_arr <<<"${ports_csv}"
  for p in "${ports_arr[@]}"; do
    flags+="-L ${bind_addr}:${p}:localhost:${p} "
  done

  flags="${flags% }"
  echo "${flags}"
}

write_target_service() {
  local target_key="$1"
  local foreign_ip="$2"
  local foreign_ssh_port="$3"
  local bind_addr="$4"
  local ports_csv="$5"
  local unit_name
  local forward_flags

  unit_name="$(service_name_for_target "${target_key}")"
  forward_flags="$(build_forward_flags "${bind_addr}" "${ports_csv}")"

  cat > "/etc/systemd/system/${unit_name}" <<UNIT
[Unit]
Description=Persistent SSH Tunnel (${target_key})
After=network-online.target zapret2.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -N -p ${foreign_ssh_port} -c aes128-gcm@openssh.com -o IPQoS=throughput -o TCPKeepAlive=yes -o PubkeyAuthentication=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -o ConnectTimeout=10 -o BatchMode=yes ${forward_flags} root@${foreign_ip}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
}

start_target_unit() {
  local key="$1"
  local unit
  unit="$(service_name_for_target "${key}")"
  systemctl start "${unit}" 2>/dev/null || true
}

restart_target_unit() {
  local key="$1"
  local unit
  unit="$(service_name_for_target "${key}")"
  systemctl restart "${unit}" 2>/dev/null || true
}

enable_target_unit() {
  local key="$1"
  local unit
  unit="$(service_name_for_target "${key}")"
  systemctl enable "${unit}" 2>/dev/null || true
}

disable_target_unit() {
  local key="$1"
  local unit
  unit="$(service_name_for_target "${key}")"
  systemctl disable "${unit}" 2>/dev/null || true
}

unit_enabled_state() {
  # Returns: enabled|disabled|other
  local unit="$1"
  local st
  st="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  case "${st}" in
    enabled) echo "enabled" ;;
    disabled) echo "disabled" ;;
    *) echo "other" ;;
  esac
}

unit_active_state() {
  # Returns: active|inactive|other
  local unit="$1"
  local st
  st="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  case "${st}" in
    active) echo "active" ;;
    inactive) echo "inactive" ;;
    *) echo "other" ;;
  esac
}

append_target_config() {
  local target_key="$1"
  local target_label="$2"
  local foreign_ip="$3"
  local foreign_ssh_port="$4"
  local bind_addr="$5"
  local ports_csv="$6"

  # Disallow '|' in label
  target_label="${target_label//|/}"

  if ! validate_bind_addr "${bind_addr}"; then
    bind_addr="0.0.0.0"
  fi

  echo "${target_key}|${target_label}|${foreign_ip}|${foreign_ssh_port}|${bind_addr}|${ports_csv}" >> "${TARGETS_FILE}"
}

prompt_target_details() {
  local default_label
  local raw_label
  local derived_key

  while true; do
    default_label="Target $(( $(wc -l < "${TARGETS_FILE}") + 1 ))"
    read -r -p "Enter a tunnel name (e.g., sweden, uk, germany-1) [${default_label}]: " raw_label
    raw_label="$(trim "${raw_label:-${default_label}}")"
    # Normalize whitespace to a single ASCII space.
    raw_label="$(echo "${raw_label}" | tr -s '[:space:]' ' ')"

    # Keep config ASCII-friendly and predictable (avoid bash =~ regex with literal spaces).
    if (( ${#raw_label} < 2 || ${#raw_label} > 32 )); then
      log_warn "Name must be 2-32 characters."
      continue
    fi
    if [[ "${raw_label}" =~ [^A-Za-z0-9_-[:space:]] ]]; then
      log_warn "Name may contain only letters/numbers/spaces/_/-."
      continue
    fi

    derived_key="$(sanitize_key "${raw_label}")"

    if target_exists "${derived_key}"; then
      log_warn "A tunnel with key '${derived_key}' already exists. Choose a different name."
      continue
    fi

    TARGET_KEY="${derived_key}"
    TARGET_LABEL="${raw_label}"
    break
  done

  log_info "Tunnel key will be: ${TARGET_KEY}"

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

  TARGET_BIND_ADDR="$(prompt_bind_address "0.0.0.0")"

  while true; do
    read -r -a TARGET_PORTS -p "Enter local ports for this tunnel (space-separated, e.g. 31 32 4000): "

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
        log_warn "Duplicate port in this tunnel: ${p}. Please re-enter all ports."
        valid="no"
        break
      fi
      if port_in_use_by_other_target "${p}"; then
        log_warn "Port ${p} is already assigned to another tunnel."
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

  if prompt_yes_no "Run ssh-copy-id for ${TARGET_LABEL} (${TARGET_IP}:${TARGET_SSH_PORT}) now?" "y"; then
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
    log_success "Passwordless SSH login configured for ${TARGET_LABEL}."
  else
    log_warn "Skipped ssh-copy-id. Make sure key-based auth is already configured."
  fi

  append_target_config "${TARGET_KEY}" "${TARGET_LABEL}" "${TARGET_IP}" "${TARGET_SSH_PORT}" "${TARGET_BIND_ADDR}" "${TARGET_PORTS_CSV}"
  ensure_nfqueue_rule "${TARGET_SSH_PORT}"
  write_target_service "${TARGET_KEY}" "${TARGET_IP}" "${TARGET_SSH_PORT}" "${TARGET_BIND_ADDR}" "${TARGET_PORTS_CSV}"
  systemctl enable --now "$(service_name_for_target "${TARGET_KEY}")" 2>/dev/null || true

  log_success "Tunnel '${TARGET_LABEL}' added with ports: ${TARGET_PORTS[*]}"
}

install_manager_command() {
  log_info "Installing management command at ${MANAGER_COMMAND} ..."
  local current_source="${BASH_SOURCE[0]}"

  if [[ -f "${current_source}" && "${current_source}" != /dev/fd/* ]]; then
    install_file 0755 "${current_source}" "${MANAGER_COMMAND}"
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

initial_setup_flow() {
  log_warn "Initial setup can optionally reset iptables and will recreate managed tunnel services."
  if ! prompt_yes_no "Continue with initial setup?" "n"; then
    log_info "Initial setup canceled."
    return 0
  fi

  ensure_storage
  ensure_packages

  if prompt_yes_no "Reset iptables rules to ACCEPT (destructive)?" "n"; then
    if typed_confirm "RESET-IPTABLES" "This will FLUSH filter/nat/mangle tables and set policies to ACCEPT."; then
      reset_iptables
    else
      log_warn "Typed confirmation did not match. Skipping iptables reset."
    fi
  else
    log_info "Skipping iptables changes (safe path)."
  fi

  systemctl stop zapret2.service 2>/dev/null || true
  systemctl disable zapret2.service 2>/dev/null || true

  stop_disable_all_tunnel_units
  remove_all_tunnel_unit_files
  kill_existing_tunnel_processes

  : > "${TARGETS_FILE}"

  install_zapret2
  select_and_apply_profile_menu
  add_target_flow
  install_manager_command

  log_success "Initial setup completed."
}

collect_targets_arrays() {
  # Outputs global arrays: T_KEYS, T_LABELS, T_IPS, T_SSH_PORTS, T_BINDS, T_PORTS_CSV
  T_KEYS=()
  T_LABELS=()
  T_IPS=()
  T_SSH_PORTS=()
  T_BINDS=()
  T_PORTS_CSV=()

  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    local parsed
    parsed="$(read_target_line "${line}")"

    local k l ip sp pc
    local bind
    IFS='|' read -r k l ip sp bind pc <<<"${parsed}"

    T_KEYS+=("${k}")
    T_LABELS+=("${l}")
    T_IPS+=("${ip}")
    T_SSH_PORTS+=("${sp}")
    T_BINDS+=("${bind}")
    T_PORTS_CSV+=("${pc}")
  done < "${TARGETS_FILE}"
}

list_targets_basic() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnel targets configured yet."
    return 0
  fi

  collect_targets_arrays

  printf "\n${C_BOLD}Configured Tunnel Targets${C_RESET}\n"
  printf "%-4s %-18s %-14s %-17s %-9s %-9s %s\n" "#" "NAME" "KEY" "FOREIGN_IP" "SSH_PORT" "BIND" "PORTS"
  printf "%-4s %-18s %-14s %-17s %-9s %-9s %s\n" "--" "------------------" "--------------" "-----------------" "---------" "---------" "----------------"

  local i
  for ((i=0; i<${#T_KEYS[@]}; i++)); do
    printf "%-4s %-18s %-14s %-17s %-9s %-9s %s\n" "$((i+1))" "${T_LABELS[$i]:0:18}" "${T_KEYS[$i]}" "${T_IPS[$i]}" "${T_SSH_PORTS[$i]}" "${T_BINDS[$i]}" "${T_PORTS_CSV[$i]//,/ }"
  done
  echo
}

remove_target_flow() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No targets to remove."
    return 0
  fi

  if ! select_target_index; then
    log_info "Canceled."
    return 0
  fi

  local target_key="${T_KEYS[${SELECTED_IDX}]}"
  local target_label="${T_LABELS[${SELECTED_IDX}]}"
  local target_ssh_port="${T_SSH_PORTS[${SELECTED_IDX}]}"
  local unit_name
  unit_name="$(service_name_for_target "${target_key}")"

  systemctl stop "${unit_name}" 2>/dev/null || true
  systemctl disable "${unit_name}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${unit_name}"

  awk -F'|' -v n="${target_key}" '$1 != n' "${TARGETS_FILE}" > "${TARGETS_FILE}.tmp"
  mv "${TARGETS_FILE}.tmp" "${TARGETS_FILE}"

  systemctl daemon-reload
  remove_nfqueue_rule_if_unused "${target_ssh_port}"

  log_success "Tunnel '${target_label}' removed."
}

edit_tunnel_flow() {
  ensure_storage
  ensure_packages

  if ! select_target_index; then
    log_info "Canceled."
    return 0
  fi

  local old_key="${T_KEYS[${SELECTED_IDX}]}"
  local old_label="${T_LABELS[${SELECTED_IDX}]}"
  local old_ip="${T_IPS[${SELECTED_IDX}]}"
  local old_ssh_port="${T_SSH_PORTS[${SELECTED_IDX}]}"
  local old_bind="${T_BINDS[${SELECTED_IDX}]}"
  local old_ports_csv="${T_PORTS_CSV[${SELECTED_IDX}]}"

  local new_label="${old_label}"
  local new_key="${old_key}"
  local new_ip="${old_ip}"
  local new_ssh_port="${old_ssh_port}"
  local new_bind="${old_bind}"
  local new_ports_csv="${old_ports_csv}"

  echo
  echo -e "${C_BOLD}Edit Tunnel${C_RESET}"
  echo "Leave fields empty to keep current values."
  echo

  local input=""

  read -r -p "Display name [${old_label}]: " input
  input="$(trim "${input}")"
  if [[ -n "${input}" ]]; then
    input="$(echo "${input}" | tr -s '[:space:]' ' ')"
    if (( ${#input} < 2 || ${#input} > 32 )); then
      log_warn "Name must be 2-32 characters. Keeping current."
    elif [[ "${input}" =~ [^A-Za-z0-9_-[:space:]] ]]; then
      log_warn "Name contains invalid characters. Keeping current."
    else
      new_label="${input}"
      local derived
      derived="$(sanitize_key "${new_label}")"
      if [[ "${derived}" != "${old_key}" ]]; then
        if ! target_exists "${derived}"; then
          if prompt_yes_no "Also change key from '${old_key}' to '${derived}' (affects systemd unit name)?" "y"; then
            new_key="${derived}"
          fi
        else
          log_warn "Derived key '${derived}' already exists. Keeping key '${old_key}'."
        fi
      fi
    fi
  fi

  read -r -p "Foreign server IP [${old_ip}]: " input
  input="$(trim "${input}")"
  if [[ -n "${input}" ]]; then
    if validate_ipv4 "${input}"; then
      new_ip="${input}"
    else
      log_warn "Invalid IP. Keeping current."
    fi
  fi

  read -r -p "Foreign SSH port [${old_ssh_port}]: " input
  input="$(trim "${input}")"
  if [[ -n "${input}" ]]; then
    if validate_port "${input}"; then
      new_ssh_port="${input}"
    else
      log_warn "Invalid SSH port. Keeping current."
    fi
  fi

  new_bind="$(prompt_bind_address "${old_bind}")"

  read -r -p "Local ports (space-separated) [${old_ports_csv//,/ }]: " input
  input="$(trim "${input}")"
  if [[ -n "${input}" ]]; then
    local -a ports=()
    read -r -a ports <<<"${input}"

    if [[ ${#ports[@]} -eq 0 ]]; then
      log_warn "No ports provided. Keeping current."
    else
      local -A seen=()
      local -a cleaned=()
      local p
      local ok="yes"
      for p in "${ports[@]}"; do
        if ! validate_port "${p}"; then
          log_warn "Invalid port: ${p}. Keeping current."
          ok="no"
          break
        fi
        if [[ -n "${seen["${p}"]+x}" ]]; then
          log_warn "Duplicate port: ${p}. Keeping current."
          ok="no"
          break
        fi
        if port_in_use_by_other_target_excluding "${old_key}" "${p}"; then
          log_warn "Port ${p} is assigned to another tunnel. Keeping current."
          ok="no"
          break
        fi
        seen["${p}"]=1
        cleaned+=("${p}")
      done

      if [[ "${ok}" == "yes" ]]; then
        new_ports_csv="$(IFS=','; echo "${cleaned[*]}")"
      fi
    fi
  fi

  local old_unit
  old_unit="$(service_name_for_target "${old_key}")"

  local new_unit
  new_unit="$(service_name_for_target "${new_key}")"

  local old_enabled old_active
  old_enabled="$(unit_enabled_state "${old_unit}")"
  old_active="$(unit_active_state "${old_unit}")"

  echo
  log_info "Planned changes:"
  echo "  Name:  ${old_label} -> ${new_label}"
  echo "  Key:   ${old_key} -> ${new_key}"
  echo "  Host:  ${old_ip}:${old_ssh_port} -> ${new_ip}:${new_ssh_port}"
  echo "  Bind:  ${old_bind} -> ${new_bind}"
  echo "  Ports: ${old_ports_csv//,/ } -> ${new_ports_csv//,/ }"

  if ! prompt_yes_no "Apply changes now?" "y"; then
    log_info "No changes applied."
    return 0
  fi

  systemctl stop "${old_unit}" 2>/dev/null || true
  systemctl disable "${old_unit}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${old_unit}"

  if [[ "${new_key}" != "${old_key}" ]]; then
    awk -F'|' -v n="${old_key}" '$1 != n' "${TARGETS_FILE}" > "${TARGETS_FILE}.tmp"
    mv "${TARGETS_FILE}.tmp" "${TARGETS_FILE}"
    append_target_config "${new_key}" "${new_label}" "${new_ip}" "${new_ssh_port}" "${new_bind}" "${new_ports_csv}"
  else
    local newline
    newline="${new_key}|${new_label//|/}|${new_ip}|${new_ssh_port}|${new_bind}|${new_ports_csv}"
    replace_target_line_in_config "${old_key}" "${newline}"
  fi

  systemctl daemon-reload

  ensure_nfqueue_rule "${new_ssh_port}"
  if [[ "${new_ssh_port}" != "${old_ssh_port}" ]]; then
    remove_nfqueue_rule_if_unused "${old_ssh_port}"
  fi

  write_target_service "${new_key}" "${new_ip}" "${new_ssh_port}" "${new_bind}" "${new_ports_csv}"

  # Restore enabled/active state from the old unit.
  if [[ "${old_enabled}" == "enabled" ]]; then
    systemctl enable "${new_unit}" >/dev/null 2>&1 || true
  else
    systemctl disable "${new_unit}" >/dev/null 2>&1 || true
  fi
  if [[ "${old_active}" == "active" ]]; then
    systemctl start "${new_unit}" >/dev/null 2>&1 || true
  fi

  if systemctl is-active --quiet "${new_unit}"; then
    log_success "Tunnel updated: ${new_label} (${new_unit})"
  else
    log_warn "Updated service is not active. Check: systemctl status ${new_unit}"
  fi
}

restart_all_tunnels() {
  ensure_storage
  ensure_zapret2_running

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No configured targets found."
    return 0
  fi

  local restarted=0
  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    local parsed
    parsed="$(read_target_line "${line}")"

    local k l ip sp bind pc
    IFS='|' read -r k l ip sp bind pc <<<"${parsed}"

    # Only ensure NFQUEUE when a tunnel is enabled or currently active.
    local unit
    unit="$(service_name_for_target "${k}")"
    local en act
    en="$(unit_enabled_state "${unit}")"
    act="$(unit_active_state "${unit}")"
    if [[ "${en}" == "enabled" || "${act}" == "active" ]]; then
      ensure_nfqueue_rule "${sp}"
    fi

    write_target_service "${k}" "${ip}" "${sp}" "${bind}" "${pc}"

    # Preserve enabled/active state.
    if [[ "${en}" == "enabled" ]]; then
      systemctl enable "${unit}" >/dev/null 2>&1 || true
    else
      systemctl disable "${unit}" >/dev/null 2>&1 || true
    fi

    if [[ "${act}" == "active" ]]; then
      systemctl restart "${unit}" >/dev/null 2>&1 || true
    fi

    restarted=$((restarted + 1))
  done < "${TARGETS_FILE}"

  log_success "Restarted/reloaded ${restarted} tunnel target(s)."
}

is_port_listening() {
  local port="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return 0
    fi
    return 1
  fi

  if command -v netstat >/dev/null 2>&1; then
    if netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return 0
    fi
    return 1
  fi

  return 1
}

target_ports_health() {
  # Input: ports_csv. Output: "ok_count/total" and returns 0 if all ok.
  local ports_csv="$1"
  local -a ports_arr=()
  IFS=',' read -r -a ports_arr <<<"${ports_csv}"

  local total=${#ports_arr[@]}
  local ok=0
  local p
  for p in "${ports_arr[@]}"; do
    if is_port_listening "${p}"; then
      ok=$((ok + 1))
    fi
  done

  echo "${ok}/${total}"
  [[ ${ok} -eq ${total} ]]
}

ssh_connectivity_check() {
  local ip="$1"
  local ssh_port="$2"

  # Best-effort quick check (key-based). Do not fail the dashboard if it fails.
  if ! command -v ssh >/dev/null 2>&1; then
    echo "N/A"
    return 0
  fi

  local cmd=(ssh -p "${ssh_port}" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"${ip}" true)

  if command -v timeout >/dev/null 2>&1; then
    if timeout 7 "${cmd[@]}" >/dev/null 2>&1; then
      echo "OK"
    else
      echo "FAIL"
    fi
  else
    if "${cmd[@]}" >/dev/null 2>&1; then
      echo "OK"
    else
      echo "FAIL"
    fi
  fi
}

status_badge() {
  local state="$1"
  case "${state}" in
    OK)   echo -e "${C_GREEN}OK${C_RESET}" ;;
    WARN) echo -e "${C_YELLOW}WARN${C_RESET}" ;;
    DOWN) echo -e "${C_RED}DOWN${C_RESET}" ;;
    *)    echo -e "${C_DIM}${state}${C_RESET}" ;;
  esac
}

dashboard_table() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnel targets configured yet."
    return 0
  fi

  collect_targets_arrays

  local zp
  zp="$(current_profile_name)"

  printf "\n${C_BOLD}Tunnel Dashboard${C_RESET}\n"
  printf "%-4s %-18s %-12s %-16s %-8s %-10s %-15s %-8s %-9s %s\n" "#" "NAME" "KEY" "FOREIGN_IP" "SSH" "ZP" "PORTS" "SVC" "LISTEN" "SSH"
  printf "%-4s %-18s %-12s %-16s %-8s %-10s %-15s %-8s %-9s %s\n" "--" "------------------" "------------" "----------------" "------" "----------" "---------------" "------" "---------" "---"

  local i
  for ((i=0; i<${#T_KEYS[@]}; i++)); do
    local key="${T_KEYS[$i]}"
    local label="${T_LABELS[$i]}"
    local ip="${T_IPS[$i]}"
    local ssh_port="${T_SSH_PORTS[$i]}"
    local ports_csv="${T_PORTS_CSV[$i]}"

    local unit
    unit="$(service_name_for_target "${key}")"

    local is_active
    is_active="$(systemctl is-active "${unit}" 2>/dev/null || true)"

    local svc_state
    case "${is_active}" in
      active) svc_state="OK" ;;
      activating|deactivating) svc_state="WARN" ;;
      failed) svc_state="DOWN" ;;
      *) svc_state="DOWN" ;;
    esac

    local listen_ratio
    listen_ratio="$(target_ports_health "${ports_csv}")"
    local listen_badge
    if [[ "${listen_ratio}" == */* ]] && [[ "${listen_ratio%/*}" == "${listen_ratio#*/}" ]]; then
      listen_badge="$(status_badge OK)"
    else
      listen_badge="$(status_badge WARN)"
    fi

    local ssh_check
    ssh_check="$(ssh_connectivity_check "${ip}" "${ssh_port}")"
    local ssh_badge
    if [[ "${ssh_check}" == "OK" ]]; then
      ssh_badge="$(status_badge OK)"
    elif [[ "${ssh_check}" == "FAIL" ]]; then
      ssh_badge="$(status_badge WARN)"
    else
      ssh_badge="${ssh_check}"
    fi

    printf "%-4s %-18s %-12s %-16s %-8s %-10s %-15s %-8b %-9b %b\n" \
      "$((i+1))" \
      "${label:0:18}" \
      "${key:0:12}" \
      "${ip:0:16}" \
      "${ssh_port}" \
      "${zp:0:10}" \
      "${ports_csv//,/ }" \
      "$(status_badge "${svc_state}")" \
      "${listen_badge} ${C_DIM}(${listen_ratio})${C_RESET}" \
      "${ssh_badge}"
  done

  echo
  echo -e "${C_DIM}Legend:${C_RESET} SVC=systemd state, LISTEN=local ports listening, SSH=quick key-based connectivity test"
}

dashboard_details() {
  local idx="$1"

  local key="${T_KEYS[$idx]}"
  local label="${T_LABELS[$idx]}"
  local ip="${T_IPS[$idx]}"
  local ssh_port="${T_SSH_PORTS[$idx]}"
  local ports_csv="${T_PORTS_CSV[$idx]}"

  local unit
  unit="$(service_name_for_target "${key}")"

  echo
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo -e "${C_BOLD} Tunnel Details: ${label}${C_RESET}"
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo -e "Name: ${label}"
  echo -e "Key:  ${key}"
  echo -e "Host: ${ip}:${ssh_port}"
  echo -e "Ports: ${ports_csv//,/ }"
  echo

  log_info "systemd status (${unit})"
  systemctl --no-pager --full status "${unit}" || true

  echo
  log_info "Listening ports"
  local -a ports_arr=()
  IFS=',' read -r -a ports_arr <<<"${ports_csv}"
  local p
  for p in "${ports_arr[@]}"; do
    if is_port_listening "${p}"; then
      echo -e "  ${C_GREEN}LISTEN${C_RESET} :${p}"
    else
      echo -e "  ${C_RED}CLOSED${C_RESET} :${p}"
    fi
  done

  echo
  log_info "SSH connectivity (key-based)"
  local check
  check="$(ssh_connectivity_check "${ip}" "${ssh_port}")"
  if [[ "${check}" == "OK" ]]; then
    log_success "SSH connectivity OK"
  else
    log_warn "SSH connectivity check failed (this does not always mean the tunnel is down)."
  fi

  if prompt_yes_no "Show last 50 journal lines for ${unit}?" "n"; then
    echo
    journalctl -u "${unit}" -n 50 --no-pager || true
  fi
}

dashboard_flow() {
  ensure_storage

  if [[ ! -s "${TARGETS_FILE}" ]]; then
    log_warn "No tunnel targets configured yet."
    return 0
  fi

  while true; do
    dashboard_table

    collect_targets_arrays
    local choice
    read -r -p "Select a tunnel for details (0 to go back): " choice

    if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice == 0 )); then
      return 0
    fi

    if [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#T_KEYS[@]} )); then
      dashboard_details $((choice - 1))
      pause_prompt
    else
      log_warn "Invalid selection."
    fi
  done
}

show_help() {
  cat <<HELP
Usage: $(basename "$0") [option]

Options:
  --menu             Open interactive menu (default)
  --initial-setup    Run initial setup flow directly
  --add-target       Add a new tunnel target directly
  --edit             Edit an existing tunnel (interactive selector)
  --power            Start/stop or enable/disable a tunnel (interactive selector)
  --dashboard        Show the tunnel dashboard (summary + drill-down)
  --profile          Select/apply zapret2 profile (Profile 1/2/3 menu)
  --restart-all      Restart/rebuild all tunnel services
  --uninstall        Uninstall everything created/managed by this script
  --install-command  Install/update ${MANAGER_COMMAND}
  -h, --help         Show this help
HELP
}

show_main_menu() {
  echo
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo -e "${C_BOLD} Zapret2 + Multi-Target SSH Tunnel Manager    ${C_RESET}"
  echo -e "${C_BOLD}==============================================${C_RESET}"
  echo "1) Initial setup (fresh install/reset + add first tunnel)"
  echo "2) Add new tunnel (server/ports)"
  echo "3) List configured tunnels"
  echo "4) Edit a tunnel"
  echo "5) Remove a tunnel"
  echo "6) Restart/rebuild all tunnel services"
  echo "7) Tunnel dashboard (pretty status + details)"
  echo "8) Change Zapret2 profile (switch /etc/zapret2.lua)"
  echo "9) Install/update management command (${MANAGER_COMMAND})"
  echo "10) Enable/Disable a tunnel (start/stop)"
  echo "11) Uninstall (remove everything managed by this script)"
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
        list_targets_basic
        pause_prompt
        ;;
      4)
        edit_tunnel_flow
        pause_prompt
        ;;
      5)
        remove_target_flow
        pause_prompt
        ;;
      6)
        restart_all_tunnels
        pause_prompt
        ;;
      7)
        dashboard_flow
        ;;
      8)
        select_and_apply_profile_menu
        pause_prompt
        ;;
      9)
        install_manager_command
        pause_prompt
        ;;
      10)
        tunnel_power_flow
        pause_prompt
        ;;
      11)
        uninstall_flow
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
    --edit)
      edit_tunnel_flow
      ;;
    --power)
      tunnel_power_flow
      ;;
    --dashboard)
      dashboard_flow
      ;;
    --profile)
      select_and_apply_profile_menu
      ;;
    --restart-all)
      restart_all_tunnels
      ;;
    --uninstall)
      uninstall_flow
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
