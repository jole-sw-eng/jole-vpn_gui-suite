# jole-vpn_gui-suite

A containerized **OpenVPN 2.6 server** with a PiVPN-style, fully configurable installer and client manager,
plus a **LAN-only HTTPS admin web UI** for setup, clients, certificates and status.

It works with the **Inseego M2000** MiFi hotspot (OpenVPN 2.4.3 client) as well as modern phones and
laptops, and has mobile-network tuning (`mssfix`, keepalive) built in.

> This repository is the public, documented packaging of jole-vpn **v2.0**. The code behaves exactly like
> v2.0; only example values in hints, comments, error messages and tests were made generic. This edition
> adds the documentation in [`docs/`](docs/).

## Documentation

| Guide | What it covers |
|---|---|
| [How it works](docs/01-how-it-works.md) | Architecture, the OpenVPN container, PKI/CA, tls-crypt, the admin UI and its guards, routing modes |
| [Setup tutorial](docs/02-setup-tutorial.md) | Step by step on a fresh Debian or Ubuntu host, from Docker to a working client profile |
| [Verification checks](docs/03-verification.md) | Proving that only the VPN port is reachable from the internet |
| [Start on boot](docs/04-start-on-boot.md) | Docker service plus the compose restart policy |
| [Hardening](docs/05-hardening.md) | lan-only routing, GCM ciphers, password auth, CRL renewal |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability privately |
| [Troubleshooting](docs/06-troubleshooting.md) | "Not allowed from this address", bind errors, port conflicts, CRL expiry |
| [Rollback, backup and removal](docs/07-rollback-and-backup.md) | Turning the UI off, stopping the server, backing up the data volume |
| [Security notes](docs/08-security-notes.md) | What must never be exposed, and why |

## Quick start (for people who have done this before)

Everything below is explained in the [setup tutorial](docs/02-setup-tutorial.md).

```bash
sudo git clone https://github.com/jole-sw-eng/jole-vpn_gui-suite /opt/jole-vpn_gui-suite
cd /opt/jole-vpn_gui-suite
sudo cp .env.example .env && sudo chmod 600 .env
sudo nano .env                      # choose loopback (default) or a LAN bind + allowlist
sudo docker compose up -d --build
sudo docker compose logs jole-vpn | grep -E 'TOKEN|Fingerprint'
```

Then open `https://127.0.0.1:8443/` on the server (or `https://<server LAN IP>:8443/` if you chose a LAN
bind), check the certificate fingerprint, paste the newest token, create the admin account, run the
**Setup wizard**, add a client, download its `.ovpn`, and forward **only the VPN port** (default
`1194/udp`) on your router. **Never forward 8443.**

### Which routing mode?

**`lan-only` is recommended for most users.** Only routes to your home-network subnets (`--lan`) are
pushed, so only that traffic goes through the tunnel; the device's normal internet traffic stays direct
on its own connection, and the container firewall drops anything else arriving over the VPN.
Choose **`full`** only if you want *all* of a device's traffic (web browsing included) to leave through
your home connection, for example on untrusted Wi-Fi. Note that the setup default is still `full`, so pick
`lan-only` explicitly. Details: [routing modes](docs/01-how-it-works.md#routing-modes).

## What the web UI does

A small HTTPS admin page (Python standard library only, no extra packages) that drives the same
`jole-vpn-setup` / `jole-vpn-client` scripts, so you never have to remember the commands:

- **Setup wizard**: every setup option (host, port, protocol, subnet, DNS, ciphers, cert type/lifetime,
  CRL lifetime, routing mode, LAN subnets, password auth, match-CN, tls-crypt, mssfix).
- **Config editor**: change settings later while **keeping the CA and all clients** (`--reconfigure`),
  or deliberately rebuild everything (type `REBUILD` to confirm).
- **Clients**: list (status, profile, password, expiry), add (mobile or **m2000/legacy** profile; generate a
  strong VPN password shown once, set your own, or none), download `.ovpn`, regenerate a profile or all
  profiles, set a new VPN password, revoke (type the name to confirm).
- **CRL**: next-update date with a warning under 30 days, one-click regenerate.
- **Status**: OpenVPN running or not, connected clients (VPN IP, source, since, bytes), **Apply / restart**.
- **Audit log** of every admin action, and admin password change.

## Settings (environment / `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `JOLE_WEB` | `1` in compose, `0` in the image | `0` = CLI only, exactly like v1 |
| `WEB_BIND` | `127.0.0.1` | host address the UI is published on; must be one specific IP, wildcard refused |
| `WEB_PORT` | `8443` | host port for the UI |
| `WEB_ALLOW_CIDRS` | (empty = any source except VPN clients) | optional source allowlist, e.g. `192.168.1.0/24` or `192.168.1.20/32`. Opening the UI from the Docker host itself arrives from the Docker bridge (e.g. `172.17.0.1`): add that too, or browse from another LAN machine |
| `WEB_ALLOW_VPN` | `no` | `yes` lets VPN clients reach the UI (not recommended) |
| `WEB_HOSTNAMES` | | extra names allowed in the `Host` header and cert SAN, e.g. `vpnadmin.lan` |
| `JOLE_WEB_ADMIN_USER` / `JOLE_WEB_ADMIN_HASH` | `admin` / empty | optional pre-set admin (hash from `web hash-password`) |
| `JOLE_VPN_PORT` / `JOLE_VPN_PROTO` | `1194` / `udp` | the VPN port Docker publishes; must match `PORT`/`PROTO` from setup |
| `WEB_ALLOW_ANY` | (unset) | escape hatch that permits a wildcard bind. **Do not set it.** |

## Security design (summary)

- **Network**: published only on `WEB_BIND`; refuses wildcard binds; never on the VPN port (startup and
  setup reject a TCP VPN port equal to the UI port). Optional source allowlist (`WEB_ALLOW_CIDRS`).
- **VPN clients cannot reach the UI** by default: the container drops `tun+` → UI traffic in `INPUT`, drops
  forwarded VPN traffic to `WEB_BIND:WEB_PORT`, and the app rejects source IPs inside the VPN subnet.
  Only `WEB_ALLOW_VPN=yes` changes that.
- **TLS** 1.2+ only, self-signed cert kept in the data volume (`web/tls/`), separate from the VPN CA.
- **Admin auth**: scrypt (N=2^15, r=8, p=1, random salt) in `web/admin.json` (mode 600); one-time first-run
  token (only its hash is kept in memory); no default credentials; constant-time comparisons.
- **Sessions**: random 256-bit IDs in memory, `__Host-` cookies with `Secure; HttpOnly; SameSite=Strict`,
  30-minute idle / 12-hour absolute timeout, all sessions dropped on admin password change.
- **CSRF**: per-session token on every authenticated POST, HMAC pre-session token on login/first-run forms,
  `Origin` checked, `Host` header checked (DNS-rebinding guard).
- **Brute force**: 5 failed logins per IP per 15 minutes, 30 per minute globally, plus a fixed delay.
- **Input**: every field validated (names, CIDRs, IPs, ports, enums) before any script runs; scripts are
  called with argument lists (never a shell); VPN passwords travel over stdin (`--password-stdin`), never argv.
- **Headers**: strict CSP (no JavaScript at all), `X-Frame-Options: DENY`, `no-store`, `nosniff`, HSTS,
  `no-referrer`.
- **Logs**: the access log records method + path only (no query strings or bodies). The audit log
  (`web/audit.log`, mode 600) records time, source IP, admin user, action, target and result, never
  passwords, tokens or keys. `.ovpn` downloads require login; the audit log notes *who downloaded which
  client*, the file contents are never logged.
- The UI process runs as root inside the container because it drives the PKI scripts; it is the
  CA's front door, so treat the admin password like the CA key.

More detail: [How it works](docs/01-how-it-works.md) and [Security notes](docs/08-security-notes.md).

## CLI (still fully supported)

The web UI is optional. Everything can be done from the command line; with the container running use
`sudo docker compose exec jole-vpn <command>`, or with it stopped `sudo docker compose run --rm jole-vpn <subcommand>`.

```bash
# 1. Interactive setup (answers stored in the persistent volume)
sudo docker compose run --rm jole-vpn setup
#    ...or unattended:
sudo docker compose run --rm jole-vpn setup -y --host vpn.example.com \
    --routing lan-only --lan 192.168.1.0/24 --cert-type rsa2048

# 2. Start the server (forward ONLY the VPN port on your router)
sudo docker compose up -d

# 3. Add clients
sudo docker compose run --rm jole-vpn client add m2000 --profile m2000
sudo docker compose run --rm jole-vpn client add phone            # mobile profile (default)
# both prompt for the VPN password (hidden); see "Client management" for --password-stdin

# 4. Copy a profile out (it contains the client's private key: handle it like a password)
sudo docker compose run --rm jole-vpn client show m2000 > m2000.ovpn
```

If you change port/proto, set `JOLE_VPN_PORT` / `JOLE_VPN_PROTO` in `.env` so compose publishes the right port.

### Setup options

Every prompt can be answered by flag, by a config file (`-c FILE`, see `examples/jole-vpn.conf.example`),
or left at the default. Precedence: flag > config file > default. `-y` never prompts.

| Flag | Config key | Default | Notes |
|---|---|---|---|
| `--host` | `PUBLIC_HOST` | (required) | Public IP / hostname / DDNS |
| `--port` | `PORT` | 1194 | |
| `--proto` | `PROTO` | udp | udp or tcp (IPv4: `udp4`/`tcp4`) |
| `--subnet` | `SUBNET` | 10.8.0.0/24 | VPN client subnet; must not overlap your LAN |
| `--dns` | `DNS` | 1.1.1.1,9.9.9.9 | pushed to clients |
| `--ciphers` | `CIPHERS` | AES-256-GCM:AES-128-GCM:AES-128-CBC | `data-ciphers` |
| `--cert-type` | `CERT_TYPE` | ec | ec (P-256) / rsa2048 / rsa4096, SHA256 signatures |
| `--cert-days` | `CERT_DAYS` | 825 | cert lifetime |
| `--crl-days` | `CRL_DAYS` | 180 | run `client gen-crl` before it expires or **all** clients are rejected |
| `--password-auth` | `PASSWORD_AUTH` | yes | password **in addition to** client cert |
| `--match-cn` | `PASSWORD_MATCH_CN` | no | username must equal cert name |
| `--tls-crypt` | `TLS_CRYPT` | yes | drops packets from anyone without the key |
| `--routing` | `ROUTING` | full | see [routing modes](docs/01-how-it-works.md#routing-modes) |
| `--lan` | `LAN_SUBNETS` | (none) | comma-separated CIDRs clients may reach; required for split / lan-only |
| `--mssfix` | `MSSFIX` | 1360 | server-side clamp |
| `--force` | | | rebuild PKI (invalidates all clients) |
| `--reconfigure` | | | keep CA + clients, rewrite config only; unset options keep current values |

### Client management

```
jole-vpn-client add <name> [--profile mobile|m2000] [--password-stdin | --no-password | --password PW]
jole-vpn-client profile <name> --profile m2000   # regenerate .ovpn
jole-vpn-client passwd <name> [--password-stdin | --password PW] # set/replace password
jole-vpn-client revoke <name>                    # revoke cert + refresh CRL + remove password
jole-vpn-client list | show <name> | gen-crl
```

**Prefer `--password-stdin`** (or the interactive prompt) over `--password PW`. `--password-stdin` reads the
password from the first line of stdin, so it never shows in the process list; `--password PW` puts the
password on the command line, where any user on the host can see it with `ps` and where it lands in shell
history. A safe pattern:

```bash
read -rs -p 'VPN password for laptop: ' PW; echo
printf '%s\n' "$PW" | sudo docker compose exec -T jole-vpn jole-vpn-client add laptop --password-stdin
unset PW
```

`printf` is a shell builtin, so the password never appears as a command-line argument of any process.
Avoid `--password PW`: anything on a command line is visible to every user on the host in the
process list (`ps`), and it also lands in your shell history.

Without any password option you're prompted (input hidden) when a terminal is attached; when
non-interactive, a random 24-char password is generated and printed once.
Profiles carry inline `<ca>`, `<cert>`, `<key>`, `<tls-crypt>`. The generator refuses to write any profile
containing script hooks (`script-security`, `up`, `down`, ...), `nice`, `mute`, or compression.

| Profile | For | Contents |
|---|---|---|
| `mobile` | phones, laptops (OpenVPN 2.5+) | udp4, `data-ciphers`, `tun-mtu 1500`, `mssfix 1360`, `keepalive 10 60` |
| `m2000` (alias `legacy`) | Inseego M2000 / OpenVPN 2.4 | minimal: `cipher AES-128-CBC`, `ncp-ciphers` incl. GCM, `auth SHA256`, `auth-user-pass`, `mssfix 1360` |

### Server hardening (generated `server.conf`)

`data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC`, `data-ciphers-fallback AES-128-CBC`, `auth SHA256`,
`tls-version-min 1.2`, `tls-crypt`, `verify-client-cert require`, `remote-cert-tls client`, `crl-verify`,
`auth-user-pass-verify` (SHA-512-crypt hashed `users.db`) + `auth-nocache`, no compression,
`mssfix 1360`, `keepalive 10 60`, drops to `nobody:nogroup`.

## Inseego M2000 notes

- Firmware ships OpenVPN 2.4.3 / OpenSSL 1.1.1: TLS 1.2 and AES-GCM negotiation work. The server pushes
  keepalive, so the M2000 profile stays minimal.
- The M2000's own VPN settings page requires a username/password: keep `PASSWORD_AUTH=yes` (the cert is still required too).
- It rejects directives like `nice` and `mute` ("invalid config file"); the m2000 profile omits them.
- RSA 2048 (`--cert-type rsa2048`) is the most widely tested choice for this device. Try EC if you like;
  fall back to RSA if the handshake fails.
- If connections stall on cellular, lower `mssfix` to 1300 (server `--mssfix 1300` and edit the profile).
- Give the M2000 its **own** cert and a **unique, long random** password. If it is lost, revoke it immediately.
- Only load profiles you generated yourself. The M2000's client will execute scripts from a profile
  (known route to root on the device), which is why this tool never emits script directives.
- Change the MiFi's default SSID, Wi-Fi password and admin password; disable WPS and WAN-side admin;
  use WPA2/WPA3; keep the firmware updated.

## Layout

```
Dockerfile, docker-compose.yml
bin/entrypoint.sh            firewall + openvpn (+ web UI and OpenVPN supervisor when JOLE_WEB=1);
                             subcommands: serve | setup | client | web | shell
bin/jole-vpn-web             admin UI launcher: serve | hash-password | reset-admin
web/jolevpn_web/             admin UI (Python stdlib): app, auth, policy, validate, commands, vpnstate
web/tests/                   unit + end-to-end tests
VERSION, .env.example
bin/jole-vpn-setup           installer
bin/jole-vpn-client          client manager
bin/jole-vpn-auth-verify     auth-user-pass-verify script
bin/jole-vpn-lib.sh          shared helpers
examples/jole-vpn.conf.example
docs/                        how it works, tutorial, verification, hardening, troubleshooting
LICENSE                      GNU GPL v3
SECURITY.md                  how to report vulnerabilities
```

## Testing

```bash
cd web && python3 -m unittest discover -s tests -t .      # needs easy-rsa for the end-to-end tests
shellcheck -x -P bin bin/*.sh bin/jole-vpn-*
```

## Roadmap

- WireGuard mode: same installer prompts, `wg` key/peer management, QR codes for phones,
  shared routing-mode firewall.
- Optional TOTP as a second factor for non-M2000 clients.
- CRL auto-refresh timer.
- Web UI: optional TOTP for the admin login; IPv6 firewall rules.

## Changelog

### 2.0 (2026-11-09)
- New LAN-only HTTPS admin web UI: setup wizard, config editor, clients (add/download/regenerate/password/revoke),
  CRL status and regenerate, server status and connected clients, apply/restart, audit log.
- `jole-vpn-setup --reconfigure`: change settings without rebuilding the CA.
- `jole-vpn-client --password-stdin` for `add` and `passwd`.
- Entrypoint supervises OpenVPN when the UI is enabled (restart on apply, waits for setup).
  Firewall blocks VPN clients from the UI.
- OpenVPN status file refreshes every 10 s (was 60 s).
- Image now includes `python3`; compose tags it `jole-vpn:2.0`.
- CLI remains backward compatible; `JOLE_WEB=0` gives exact v1 runtime behaviour.

### 1.0
- OpenVPN container, installer (`jole-vpn-setup`), client manager (`jole-vpn-client`), password auth,
  CRL, routing modes full/split/lan-only enforced by iptables, mobile and M2000 legacy profiles.

## License

Copyright (C) 2026 jole-sw-eng

This program is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
License for more details. The full text is in [`LICENSE`](LICENSE).
