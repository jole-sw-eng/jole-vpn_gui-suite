#!/usr/bin/env bash
# Shared helpers for jole-vpn scripts. Sourced, not executed.
# shellcheck disable=SC2034

JOLE_DIR="${JOLE_DIR:-/etc/jole-vpn}"
CONF_FILE="${CONF_FILE:-$JOLE_DIR/jole-vpn.conf}"
PKI_DIR="$JOLE_DIR/pki"
CLIENT_DIR="$JOLE_DIR/clients"
USERS_DB="$JOLE_DIR/users.db"
SERVER_CONF="$JOLE_DIR/server.conf"
TC_KEY="$JOLE_DIR/tc.key"
EASYRSA_BIN="${EASYRSA_BIN:-}"

die()  { echo "jole-vpn: error: $*" >&2; exit 1; }
info() { echo "jole-vpn: $*" >&2; }

find_easyrsa() {
  if [[ -n "$EASYRSA_BIN" && -x "$EASYRSA_BIN" ]]; then return 0; fi
  local c
  for c in /usr/share/easy-rsa/easyrsa /usr/local/share/easy-rsa/easyrsa "$(command -v easyrsa 2>/dev/null)"; do
    if [[ -n "$c" && -x "$c" ]]; then EASYRSA_BIN="$c"; return 0; fi
  done
  die "easy-rsa not found (set EASYRSA_BIN)"
}

easyrsa() {
  find_easyrsa
  EASYRSA_PKI="$PKI_DIR" EASYRSA_BATCH=1 "$EASYRSA_BIN" "$@"
}

load_conf() {
  [[ -f "$CONF_FILE" ]] || die "config not found: $CONF_FILE (run jole-vpn-setup first)"
  # shellcheck source=/dev/null
  source "$CONF_FILE"
}

valid_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }

# CIDR (a.b.c.d/n) -> "network netmask"
cidr_to_netmask() {
  local ip="${1%/*}" bits="${1#*/}" mask="" i octet
  for i in 1 2 3 4; do
    if (( bits >= 8 )); then octet=255; bits=$((bits-8))
    else octet=$(( 256 - (1 << (8-bits)) )); (( bits == 0 )) && octet=0; bits=0; fi
    mask+="${octet}"; [[ $i -lt 4 ]] && mask+="."
  done
  echo "$ip $mask"
}

# Files read by openvpn AFTER it drops to nobody:nogroup (CRL, user DB).
fix_perms() {
  local grp=nogroup
  getent group "$grp" >/dev/null 2>&1 || grp=nobody
  getent group "$grp" >/dev/null 2>&1 || return 0
  [[ $EUID -eq 0 ]] || return 0
  chmod 711 "$JOLE_DIR" "$PKI_DIR" 2>/dev/null || true
  [[ -f "$PKI_DIR/crl.pem" ]] && chmod 644 "$PKI_DIR/crl.pem"
  if [[ -f "$USERS_DB" ]]; then chgrp "$grp" "$USERS_DB"; chmod 640 "$USERS_DB"; fi
  return 0
}
