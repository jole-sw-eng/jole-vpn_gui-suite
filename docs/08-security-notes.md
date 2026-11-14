# Security notes

## The two rules

1. **Never forward the admin port (8443) on your router**, and never publish it on `0.0.0.0`. The admin
   page controls the CA: whoever gets in can issue themselves a VPN profile.
2. **Turn UPnP off** on your router, so no device or container can open ports without you.

Only the VPN port (`JOLE_VPN_PORT`, default `1194/udp`) is meant to face the internet. With tls-crypt on,
it drops every packet that is not signed with your tls-crypt key.

## Exposure summary

| Port | Bound on the host | Who may reach it |
|---|---|---|
| VPN, default `1194/udp` | all addresses | the internet, via one router forward |
| admin UI, default `8443/tcp` | `WEB_BIND` only (`127.0.0.1` by default) | the server itself, or the LAN sources in `WEB_ALLOW_CIDRS`; never VPN clients |

## Host

- Docker Engine **28 or newer** (older engines let LAN neighbours reach loopback-bound ports).
- Don't add users to the `docker` group (it is root-equivalent); use `sudo docker compose`.
- `.env` mode 600; never commit it. `.gitignore` already excludes `.env`, PKI files, keys, `users.db`,
  `.ovpn`, `jole-vpn.conf` and the UI's data.
- Docker inserts its own iptables rules for published ports, which host firewalls such as `ufw` do not
  filter. Rely on the bind address, not on `ufw`, to keep 8443 private.
- With no allowlist, any local user or process on the server can reach the login page. The admin password
  still protects it; on a shared machine, set an allowlist or use SSH tunnelling from a single admin.

## Secrets

- Treat each `.ovpn` like a password: it contains a private key and the tls-crypt key.
- Treat the admin password like the CA key. Store it in a password manager.
- The first-run token is single-use; never share it.
- Back up the data volume encrypted; it holds the CA.

## Devices

- One client (cert + password) per device. Revoke lost devices immediately.
- Only import profiles you generated yourself. Some devices (including the Inseego M2000) will run scripts
  embedded in a profile; this tool refuses to write any script directives.
- For MiFi hotspots: change default Wi-Fi/admin passwords, disable WPS and WAN-side admin, keep firmware
  updated.

## Reporting

Report security problems privately as described in [SECURITY.md](../SECURITY.md). Please do not open
public issues for security bugs.
