#!/usr/bin/env bash
# Container entrypoint: apply firewall per routing mode, then run OpenVPN.
# With JOLE_WEB=1 it also runs the LAN-only admin web UI and supervises OpenVPN
# (the UI's "Apply / restart" stops OpenVPN; this loop reloads config + firewall
# and starts it again). With JOLE_WEB unset/0 behaviour is exactly as in v1.
set -euo pipefail
# shellcheck source=jole-vpn-lib.sh
source /usr/local/bin/jole-vpn-lib.sh

firewall() {
  local out_if ipt=iptables
  command -v iptables >/dev/null || { info "iptables missing; skipping firewall"; return; }
  out_if=$(ip route show default | awk '{print $5; exit}')
  [[ -n "$out_if" ]] || die "no default route"
  IFS=',' read -r -a lan <<< "${LAN_SUBNETS:-}"
  $ipt -N JOLE_FWD 2>/dev/null || $ipt -F JOLE_FWD
  $ipt -C FORWARD -j JOLE_FWD 2>/dev/null || $ipt -I FORWARD 1 -j JOLE_FWD
  $ipt -A JOLE_FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # never client-to-client
  $ipt -A JOLE_FWD -i tun+ -o tun+ -j DROP
  local c
  # Admin UI is never reachable from VPN clients unless WEB_ALLOW_VPN=yes
  if [[ "${JOLE_WEB:-0}" == 1 && "${WEB_ALLOW_VPN:-no}" != yes ]]; then
    $ipt -C INPUT -i tun+ -p tcp --dport "${WEB_LISTEN_PORT:-8443}" -j DROP 2>/dev/null \
      || $ipt -I INPUT 1 -i tun+ -p tcp --dport "${WEB_LISTEN_PORT:-8443}" -j DROP
    case "${WEB_BIND:-}" in
      ''|0.0.0.0|::|127.*) ;;
      *) $ipt -A JOLE_FWD -i tun+ -d "$WEB_BIND" -p tcp --dport "${WEB_PORT:-8443}" -j DROP;;
    esac
  fi
  for c in "${lan[@]}"; do [[ -n "$c" ]] && $ipt -A JOLE_FWD -i tun+ -s "$SUBNET" -d "$c" -j ACCEPT; done
  if [[ "$ROUTING" == full ]]; then
    # internet yes, but block private ranges not explicitly allowed above
    for c in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
      $ipt -A JOLE_FWD -i tun+ -d "$c" -j DROP
    done
    $ipt -A JOLE_FWD -i tun+ -s "$SUBNET" -o "$out_if" -j ACCEPT
  fi
  $ipt -A JOLE_FWD -i tun+ -j DROP
  $ipt -t nat -C POSTROUTING -s "$SUBNET" -o "$out_if" -j MASQUERADE 2>/dev/null \
    || $ipt -t nat -A POSTROUTING -s "$SUBNET" -o "$out_if" -j MASQUERADE
  info "firewall applied (mode=$ROUTING, lan=${LAN_SUBNETS:-none})"
}

OVPN_PID="${JOLE_OVPN_PIDFILE:-/run/jole-vpn/openvpn.pid}"
export JOLE_OVPN_PIDFILE="$OVPN_PID"
WEB_PID=""
CHILD=""

stop_all() {
  [[ -n "$CHILD" ]] && kill "$CHILD" 2>/dev/null
  [[ -n "$WEB_PID" ]] && kill "$WEB_PID" 2>/dev/null
  wait 2>/dev/null
  exit 0
}

serve_with_web() {
  mkdir -p "$(dirname "$OVPN_PID")" /dev/net; [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
  /usr/local/bin/jole-vpn-web serve &
  WEB_PID=$!
  trap stop_all TERM INT
  local backoff=2 waiting_msg=no
  while kill -0 "$WEB_PID" 2>/dev/null; do
    if [[ -f "$CONF_FILE" && -f "$SERVER_CONF" ]]; then
      # subshell: re-read config each time so UI changes take effect on restart
      # (set -e must not be in an || context, or bash ignores it inside the subshell)
      set +e; ( set -e; load_conf; fix_perms; firewall ); rc=$?; set -e
      if (( rc != 0 )); then
        info "config/firewall failed (rc=$rc); retrying in 10s"; sleep 10 & CHILD=$!; wait "$CHILD" || true; continue
      fi
      openvpn --config "$SERVER_CONF" --writepid "$OVPN_PID" &
      CHILD=$!
      local started=$SECONDS
      wait "$CHILD" || true
      rm -f "$OVPN_PID"
      info "openvpn exited; restarting"
      if (( SECONDS - started < 10 )); then backoff=$(( backoff < 30 ? backoff * 2 : 30 )); else backoff=2; fi
      sleep "$backoff" & CHILD=$!; wait "$CHILD" || true
    else
      [[ $waiting_msg == yes ]] || info "not configured yet: finish setup in the web UI (or: docker compose run --rm jole-vpn setup)"
      waiting_msg=yes
      sleep 10 & CHILD=$!; wait "$CHILD" || true
    fi
  done
  die "web UI exited; stopping container"
}

case "${1:-serve}" in
  serve)
    if [[ "${JOLE_WEB:-0}" == 1 ]]; then serve_with_web; fi
    load_conf
    [[ -f "$SERVER_CONF" ]] || die "no server.conf; run: docker compose run --rm jole-vpn setup"
    mkdir -p /dev/net; [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
    fix_perms
    firewall
    exec openvpn --config "$SERVER_CONF"
    ;;
  setup)  shift; exec /usr/local/bin/jole-vpn-setup "$@";;
  client) shift; exec /usr/local/bin/jole-vpn-client "$@";;
  web)    shift; exec /usr/local/bin/jole-vpn-web "$@";;
  shell)  exec bash;;
  *) exec "$@";;
esac
