# How it works

This page explains every moving part, so you know what you are running before you expose anything.
All statements here are taken from the code in this repository (`bin/`, `web/jolevpn_web/`,
`docker-compose.yml`, `Dockerfile`).

## The big picture

```
                      Internet
                         |
            router: forwards ONLY the VPN port (default 1194/udp)
                         |
  +----------------------+-------------------------------------------+
  | Docker host (Debian/Ubuntu)                                      |
  |                                                                  |
  |   host port 1194/udp  ----->  +-------------------------------+  |
  |                               | container "jole-vpn"          |  |
  |   WEB_BIND:8443/tcp  ------>  |  - OpenVPN 2.6 server (tun0)  |  |
  |   (127.0.0.1 or a LAN IP,     |  - iptables firewall          |  |
  |    never 0.0.0.0, never       |  - admin web UI (HTTPS 8443)  |  |
  |    forwarded on the router)   |  - easy-rsa PKI scripts       |  |
  |                               +---------------+---------------+  |
  |                                               |                  |
  |                         Docker volume "jole-vpn-data"            |
  |                         (/etc/jole-vpn: CA, keys, users, config) |
  +------------------------------------------------------------------+
```

One container runs everything. It is built from `debian:trixie-slim` with `openvpn`, `easy-rsa`,
`openssl`, `iptables`, `iproute2` and `python3`. Nothing else is installed: the web UI uses only the
Python standard library.

`docker-compose.yml` gives the container:

- `cap_add: NET_ADMIN` and the `/dev/net/tun` device, so OpenVPN can create its tunnel interface and the
  entrypoint can write iptables rules **inside the container's own network namespace**;
- `net.ipv4.ip_forward=1` (again only inside the container), so VPN clients can be routed onward;
- two published ports: the VPN port (`${JOLE_VPN_PORT:-1194}/${JOLE_VPN_PROTO:-udp}` on all host
  addresses, because the router forwards it) and the admin UI (`${WEB_BIND:-127.0.0.1}:${WEB_PORT:-8443}`,
  only on the one address you choose);
- a named volume `jole-vpn-data` mounted at `/etc/jole-vpn`, where every secret lives;
- `restart: unless-stopped`.

## Start-up sequence (`bin/entrypoint.sh`)

With `JOLE_WEB=1` (the compose default):

1. The admin UI (`jole-vpn-web serve`) starts in the background.
2. A supervisor loop waits until both `jole-vpn.conf` and `server.conf` exist. Until then it logs
   `not configured yet: finish setup in the web UI` every 10 seconds.
3. Once configured, it re-reads the config, fixes file permissions, applies the firewall, and runs
   OpenVPN. If OpenVPN exits (for example after **Apply / restart** in the UI) it is started again with a
   short back-off, re-reading the config and firewall each time.
4. If the web UI process exits, the container stops (and Docker's restart policy brings it back).

With `JOLE_WEB=0` the behaviour is exactly the old CLI-only v1: load config, apply firewall,
`exec openvpn`. The container then refuses to start until setup has been run from the CLI.

## PKI and certificate authority

`jole-vpn-setup` (called by the wizard, or directly) uses **easy-rsa** to build a private CA inside the
data volume:

- `pki/ca.crt` and the CA key (CN `jole-vpn-ca`, 10-year CA lifetime);
- a server certificate named `server`;
- one certificate per client, created by `jole-vpn-client add <name>`;
- a certificate revocation list `pki/crl.pem`.

Key type is `ec` (P-256) by default, or `rsa2048` / `rsa4096`; signatures use SHA-256. Client and server
certificates live `CERT_DAYS` (default 825). OpenVPN checks every connecting client against the CRL
(`crl-verify`).

**The CRL has its own expiry date** (`CRL_DAYS`, default 180). When it passes, OpenVPN refuses
**every** client. Renew it with `jole-vpn-client gen-crl` or the UI's **Regenerate CRL** button; the
dashboard warns when fewer than 30 days remain. See [Hardening](05-hardening.md#crl-renewal).

Revoking a client (`revoke`) marks its certificate revoked, regenerates the CRL, removes its password
and deletes its `.ovpn`. OpenVPN re-reads the CRL on each new connection.

`--force` (or **Rebuild** + typing `REBUILD` in the UI) creates a **new CA**: every existing client
profile stops working. `--reconfigure` keeps the CA and clients and only rewrites the configuration.

## tls-crypt

With `TLS_CRYPT=yes` (default) setup generates a static key `tc.key`, the server uses `tls-crypt`, and
every client profile embeds the same key. Each control-channel packet is encrypted and authenticated with
it, so packets from anyone who does not hold a profile are dropped **before** the TLS handshake starts.
To a port scanner the VPN port gives no response. This is why it is reasonable to expose the VPN port to
the internet. Keep it on.

## Client authentication

A client must present:

1. a certificate signed by this CA, not revoked (`verify-client-cert require`, `remote-cert-tls client`,
   `crl-verify`); and
2. with `PASSWORD_AUTH=yes` (default), a username and password checked by `bin/jole-vpn-auth-verify`
   against `users.db` (SHA-512-crypt hashes). With `PASSWORD_MATCH_CN=yes` the username must also equal
   the certificate name.

Passwords must be at least 12 characters. The server uses `auth-nocache` and never logs them.

## Server configuration

`server.conf` is generated, never hand-edited. Key settings: `tls-version-min 1.2`, `data-ciphers` from
`CIPHERS` (default `AES-256-GCM:AES-128-GCM:AES-128-CBC`), `data-ciphers-fallback AES-128-CBC`,
`auth SHA256`, no compression, `keepalive 10 60`, `mssfix` (default 1360, suits mobile networks),
`topology subnet`, and the process drops to `nobody:nogroup` after start.

## Client profiles

`jole-vpn-client` writes `clients/<name>.ovpn` with the CA, the client certificate and key, and the
tls-crypt key inlined. A profile is a complete credential: **treat it like a password**.

- `mobile` (default): for OpenVPN 2.5+ apps on phones and laptops.
- `m2000` (alias `legacy`): only directives OpenVPN 2.4.3 accepts, for the Inseego M2000 MiFi:
  `cipher AES-128-CBC` plus `ncp-ciphers AES-128-GCM:AES-256-GCM:AES-128-CBC`, so a GCM cipher can still
  be negotiated.

Every profile is checked after writing; if it contains a script hook (`up`, `down`, `script-security`,
`plugin`, ...), `nice`, `mute` or compression, it is deleted and the command fails.

## Routing modes

Set with `ROUTING` (`--routing`) plus `LAN_SUBNETS` (`--lan`). They control two things: which routes
the server **pushes** to clients (from `bin/jole-vpn-setup`), and what the container firewall
**forwards** (from `bin/entrypoint.sh`).

| Mode | Pushed to clients | Firewall in the container |
|---|---|---|
| `full` (default) | `redirect-gateway def1` (all traffic through the VPN) + a route for each `--lan` subnet | allows each `--lan` subnet; drops every other private range (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10); allows the internet |
| `split` | only a route for each `--lan` subnet | allows the `--lan` subnets; drops everything else |
| `lan-only` | only a route for each `--lan` subnet | allows the `--lan` subnets; drops everything else |

In the current code `split` and `lan-only` produce identical rules; both require at least one `--lan`
subnet. With either of them the client's normal internet traffic does **not** enter the tunnel at all
(no default route is pushed), so a MiFi hotspot keeps using its own cellular connection for the internet
and only your LAN subnets go through the VPN.

In every mode:

- client-to-client traffic is dropped;
- VPN traffic leaving the container is masqueraded (NAT) to the host's address;
- DNS servers from `DNS` are pushed to clients.

## The admin web UI

`web/jolevpn_web/` is a small HTTPS server (Python stdlib). It never runs commands through a shell: it
validates every form field and calls `jole-vpn-setup` / `jole-vpn-client` with argument lists, sending
passwords over stdin.

### Where it listens

Inside the container the UI listens on `0.0.0.0:8443` (`WEB_LISTEN`). That is only the container's own
network namespace. Docker publishes it on the host **only** at `WEB_BIND:WEB_PORT`.

`policy.check_bind()` refuses to start the UI if `WEB_BIND` is empty or a wildcard (`0.0.0.0`, `::`,
`*`, `[::]`) unless `WEB_ALLOW_ANY=yes` is set (don't), and `WEB_BIND` must be an IP address, not a
name. Compose defaults `WEB_BIND` to `127.0.0.1`, so if you remove the line from `.env` you get the
loopback bind.

### HTTPS certificate

On first start the UI creates a self-signed EC certificate (825 days, CN `jole-vpn-admin`) in the
volume at `web/tls/`, **separate from the VPN CA**. Its names are `localhost`, `127.0.0.1`, the
`WEB_BIND` address and any `WEB_HOSTNAMES`. Every start logs its SHA-256 fingerprint
(`... Fingerprint=AA:BB:...`). Compare that with what your browser shows before you accept the warning.
TLS 1.2 is the minimum.

### Guards applied to every request (`policy.py`, `app.py: gate()`)

1. **Source-IP allowlist.** `source_allowed()`:
   - rejects any source inside the VPN subnet (`SUBNET` from setup) unless `WEB_ALLOW_VPN=yes`;
   - if `WEB_ALLOW_CIDRS` is set, accepts only sources inside one of those networks;
   - if `WEB_ALLOW_CIDRS` is empty, accepts any other source.

   A refused source gets `403 Not allowed from this address.`

   Which source address the app sees depends on where you browse from. A browser on another LAN machine
   arrives with its real LAN address (rootful Docker's NAT keeps it). A browser on the Docker host itself
   usually arrives from the Docker bridge gateway (for example `172.17.0.1`), not from `127.0.0.1`.
   With the loopback bind and an empty allowlist that is fine; with an allowlist you would need to add
   the bridge address too.

2. **Host-header guard (DNS-rebinding protection).** `host_allowed()` accepts the request only if the
   `Host` header is `localhost`, `127.0.0.1`, `::1`, the `WEB_BIND` address, or a name listed in
   `WEB_HOSTNAMES`. Otherwise you get `421 Unexpected Host header`. Browse by IP address, or add your
   name to `WEB_HOSTNAMES`.

3. **Origin check** on every POST: the `Origin` must be `https://` and pass the same Host rule.

### VPN clients are blocked from the UI

Three independent layers, unless `WEB_ALLOW_VPN=yes`:

- the container firewall drops TCP to the UI port arriving on any `tun` interface (`INPUT`);
- if `WEB_BIND` is a LAN address, it also drops VPN traffic forwarded to `WEB_BIND:WEB_PORT`;
- the app refuses any source address inside the VPN subnet.

So a laptop that reaches your LAN **through** the VPN cannot open the admin page, by design. Manage the
server from the LAN.

### First run and login

There is no default password. Until an admin exists, the UI logs a one-time
`FIRST-RUN SETUP TOKEN` (only its hash is kept in memory). A new token is printed on every restart and
whenever the first-run page needs one; **use the newest line**. The token is consumed when the admin
account is created.

Admin passwords (12+ characters) are stored as scrypt hashes in `web/admin.json`. Sessions time out after
30 minutes idle or 12 hours, and failed logins are rate-limited (5 per IP per 15 minutes, 30 per minute
globally).

### Audit log

Every admin action is appended to `web/audit.log` (time, source IP, user, action, target, result).
Passwords, tokens, keys and profile contents are never written.

## Where your data lives

Everything is in the `jole-vpn-data` volume (`/etc/jole-vpn` in the container):

| Path | Contents |
|---|---|
| `jole-vpn.conf` | your setup answers |
| `server.conf` | generated OpenVPN config |
| `pki/` | CA, server and client certificates and keys, CRL |
| `tc.key` | tls-crypt key |
| `users.db` | VPN password hashes |
| `clients/*.ovpn` | client profiles |
| `web/admin.json`, `web/tls/`, `web/audit.log` | admin account, UI certificate, audit log |

Docker names the volume `<project>_jole-vpn-data`, where the project is the folder name you cloned into
(see `sudo docker volume ls`). Nothing secret is stored in the repository folder except your `.env`.
