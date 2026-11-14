# Setup tutorial (fresh Debian or Ubuntu host)

This walks through a complete install, from a bare server to a client that connects from outside your
network. Read [How it works](01-how-it-works.md) first if you want to know what each step does.

Throughout this guide the example addresses are placeholders. **Replace them with your own**:

| Placeholder | Meaning | Example |
|---|---|---|
| `<server LAN IP>` | the Docker host's address on your home/office network | `192.168.1.10` |
| `<admin PC IP>` | the machine you will manage it from, if not the server itself | `192.168.1.20` |
| `<LAN subnet>` | your network range | `192.168.1.0/24` |
| `<public host>` | your public IP or a DDNS name that points to it | `vpn.example.com` |

## 0. Before you start

You need:

- a 64-bit Debian 12/13 or Ubuntu 22.04/24.04 machine that stays on, with a **fixed LAN address**
  (set a DHCP reservation for it on your router);
- admin access to your router (for one port forward);
- a public IPv4 address, or a DDNS name if your ISP changes it. Carrier-grade NAT (CGNAT) setups, where
  your router itself does not get a public address, cannot accept incoming VPN connections;
- a VPN port that is free on the router. The default is `1194/udp`. If another VPN on your network already
  uses it, pick another port (for example `1195/udp`) and use it everywhere below.

Run every command from your own login with `sudo`. You do not need to be logged in as root.

## 1. Install Docker Engine 28 or newer

Install Docker from Docker's own repository; distribution packages (`docker.io`) can be older than 28.

Debian:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Ubuntu: the same commands with `debian` replaced by `ubuntu` in both URLs.
Check Docker's current instructions at <https://docs.docker.com/engine/install/> if anything fails.

Check the version:

```bash
sudo docker version --format '{{.Server.Version}}'    # must be 28.0 or newer
sudo docker compose version
```

**Why 28+?** Docker Engine 28.0 fixed two issues that matter here: hosts on the same LAN could reach ports
published only on `127.0.0.1`, and could connect directly to a container's published ports through its
internal IP. On older engines the loopback bind for the admin UI is not a real boundary.

### Do not add yourself to the `docker` group

Membership in the `docker` group is equivalent to passwordless root: anyone in it can start a container
that mounts the host's filesystem. Instead, prefix each command with `sudo` (`sudo docker compose ...`),
so every action needs your password and is logged by sudo. This guide always does that.

## 2. Get the code

```bash
sudo git clone https://github.com/jole-sw-eng/jole-vpn_gui-suite /opt/jole-vpn_gui-suite
cd /opt/jole-vpn_gui-suite
git log -1 --oneline
```

All remaining commands run from this folder. The folder name becomes the Docker Compose project name,
so the data volume will be called `jole-vpn_gui-suite_jole-vpn-data`.

## 3. Create `.env`

```bash
sudo cp .env.example .env
sudo chmod 600 .env
```

`.env` may later hold an admin password hash; mode 600 keeps it readable by root only. It is listed in
`.gitignore`, so it is never committed.

## 4. Choose where the admin page listens

Decide now. Both options keep the admin page off the internet.

### Option A: loopback only (smallest exposure, recommended)

Use this if you can sit at the server, or reach it over SSH.

```ini
WEB_BIND=127.0.0.1
WEB_PORT=8443
WEB_ALLOW_CIDRS=
```

(This is what `.env.example` already contains.) Nothing else on your LAN can reach the page at all. You
browse to `https://127.0.0.1:8443/` on the server. From another machine, use an SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:8443 <user>@<server LAN IP>
# then open https://127.0.0.1:8443/ on that machine
```

Leave `WEB_ALLOW_CIDRS` empty here: a browser on the server reaches the app from the Docker bridge
address, and an empty allowlist accepts it (VPN clients are still refused).

### Option B: LAN address with an allowlist

Use this to manage the server from another computer on the same network.

```ini
WEB_BIND=<server LAN IP>            # e.g. 192.168.1.10
WEB_PORT=8443
WEB_ALLOW_CIDRS=<admin PC IP>/32    # e.g. 192.168.1.20/32, or your whole <LAN subnet>
```

Find the addresses with `ip -4 -br addr` on each machine. Then:

- give **both** machines DHCP reservations. If the server's address changes, Docker cannot publish the
  port and the container does not start. If the admin PC's address changes, the page refuses it until
  you edit `.env` and run `sudo docker compose up -d`;
- browsing from the server itself will be refused with this allowlist (it arrives from the Docker
  bridge). Use the admin PC.

### Either way

- Leave `WEB_ALLOW_VPN` unset (default `no`).
- Never set `WEB_ALLOW_ANY` and never use `0.0.0.0`.
- **Never forward `WEB_PORT` (8443) on your router.**

Edit with `sudo nano .env`. Put comments on their own lines, not after a value.

## 5. Set the VPN port

In `.env`:

```ini
JOLE_VPN_PORT=1194
JOLE_VPN_PROTO=udp
```

Change these only if you need a different port, and use the same values in the setup wizard (step 9) and
on the router (step 12). UDP is best; use TCP only if UDP is blocked where your clients are.

## 6. Build and start

```bash
sudo docker compose up -d --build
sudo docker compose ps
```

The first build downloads Debian packages and takes a few minutes. The container starts the admin UI;
OpenVPN waits until setup is finished.

## 7. Get the first-run token and the certificate fingerprint

```bash
sudo docker compose logs jole-vpn | grep -E 'TOKEN|Fingerprint'
```

You will see lines like:

```
jole-vpn-web: HTTPS certificate sha256 Fingerprint=3A:9F:...:C1
jole-vpn-web: no admin account yet. FIRST-RUN SETUP TOKEN (one-time): <long random string>
```

- The token works **once**, and a new one is printed on every restart: always use the **newest** line.
- Do not paste the token anywhere else; it lets whoever has it create the admin account.

## 8. Open the page, check the fingerprint, create the admin

1. Browse to `https://127.0.0.1:8443/` (option A) or `https://<server LAN IP>:8443/` (option B).
2. The browser warns that the certificate is self-signed. Open the certificate details and compare its
   **SHA-256 fingerprint** with the `Fingerprint=` line from step 7. Continue only if they match.
3. On **Create the admin account**, paste the token, choose a username and a password of at least 12
   characters (store it in a password manager), and submit.

Alternative without a token: generate a hash and put it in `.env`:

```bash
sudo docker compose run --rm jole-vpn web hash-password    # prints scrypt:...
# then in .env:  JOLE_WEB_ADMIN_USER=admin   JOLE_WEB_ADMIN_HASH=scrypt:...
sudo docker compose up -d
```

## 9. Run the setup wizard (builds the CA)

Click **Setup / config**. Each field has a hint. Recommended answers:

| Field | What to enter |
|---|---|
| Public hostname / DDNS / IP | `<public host>`: what clients dial from outside |
| VPN port / Protocol | the same as `JOLE_VPN_PORT` / `JOLE_VPN_PROTO` in `.env` |
| VPN client subnet | keep `10.8.0.0/24` unless it overlaps your LAN |
| DNS servers | `1.1.1.1,9.9.9.9`, or your router's LAN IP (e.g. `192.168.1.1`) if you want local names |
| Data ciphers | keep the default; it keeps `AES-128-CBC` for the M2000 |
| Certificate key type | `ec`, or `rsa2048` if you will use an Inseego M2000 |
| Certificate / CRL lifetime | keep 825 / 180, and note the CRL date (see [Hardening](05-hardening.md#crl-renewal)) |
| Password + certificate | **yes** |
| Username must equal cert name | your choice; yes is stricter |
| tls-crypt | **yes** |
| Routing mode | **`lan-only` (recommended)**: only your home-network subnets go through the tunnel, the device's internet stays direct. `full`: all of the device's traffic goes through your home. The wizard's default is `full`, so change it. See below |
| LAN subnets | the narrowest range clients need, e.g. `<LAN subnet>` or a single host `192.168.1.50/32`. Required for `lan-only`/`split` |
| Server mssfix | keep `1360` |

### Choosing the routing mode

**Use `lan-only` unless you have a reason not to.** The server pushes routes only for the subnets in
*LAN subnets*, so only traffic to your home network enters the tunnel. Everything else (web browsing,
streaming, app updates) keeps using the device's own internet connection, which is faster, uses less of
your home upload bandwidth, and keeps working normally if the tunnel drops. A MiFi hotspot on `lan-only`
keeps giving its users direct cellular internet while they reach home machines through the VPN.

Choose **`full`** if you want **all** of a device's traffic to leave through your home connection, for
example to protect browsing on untrusted Wi-Fi or to appear to be at home. In `full` mode the container
still blocks every private range except your *LAN subnets*. (`split` currently behaves like `lan-only`.)

You can switch later without rebuilding the CA; see [Hardening](05-hardening.md#1-use-lan-only-routing-with-the-narrowest-subnet).

Click **Save and build the CA**. It can take a minute (several with rsa4096). OpenVPN starts
automatically within about 10 seconds; the dashboard shows **running**.

CLI equivalent (unattended):

```bash
sudo docker compose exec jole-vpn jole-vpn-setup -y --host vpn.example.com --port 1194 --proto udp \
    --routing lan-only --lan 192.168.1.0/24 --cert-type rsa2048
```

## 10. Add a client

Click **Clients** → **Add a client**:

- **Name**: letters, digits, `.`, `_`, `-`. It is also the VPN username.
- **Profile**: `mobile` for phones and laptops (OpenVPN 2.5+), `m2000` for an Inseego M2000 MiFi or other
  OpenVPN 2.4 clients.
- **VPN password**: *generate* (shown once, copy it now), *set my own* (12+ characters), or *none*
  (the client cannot connect while password auth is on).

CLI equivalent. Run without a password option and you are prompted (input hidden):

```bash
sudo docker compose exec jole-vpn jole-vpn-client add laptop                  # mobile profile
sudo docker compose exec jole-vpn jole-vpn-client add m2000 --profile m2000   # m2000 profile
```

For scripts, pass the password on stdin with `--password-stdin` rather than `--password PW`:

```bash
read -rs -p 'VPN password for laptop: ' PW; echo
printf '%s\n' "$PW" | sudo docker compose exec -T jole-vpn jole-vpn-client add laptop --password-stdin
unset PW
```

`printf` is a shell builtin, so the password never appears as a command-line argument of any process.
Avoid `--password PW`: anything on a command line is visible to every user on the host in the
process list (`ps`), and it also lands in your shell history.

### Inseego M2000 MiFi

1. Create a client with the `m2000` profile and its own long random password. Do not reuse it.
2. Download the `.ovpn` and import it in the M2000's VPN settings, with the username (the client name)
   and password.
3. If the handshake fails with an `ec` CA, rerun setup with `rsa2048`. Note that changing the key type
   needs a rebuild, which creates a new CA and invalidates every client.
4. If connections stall on cellular, lower mssfix to 1300 (server `--mssfix 1300` and in the profile).
5. Change the hotspot's default Wi-Fi and admin passwords, disable WPS and WAN-side admin.

## 11. Download the profile

On **Clients**, click **download .ovpn**. Or from the CLI:

```bash
sudo docker compose exec jole-vpn jole-vpn-client show laptop > laptop.ovpn
chmod 600 laptop.ovpn
```

The profile contains the client's private key and the tls-crypt key. Move it to the device over a
trusted path (USB, or an encrypted channel), import it, then delete the copy. Never email it or commit it.

## 12. Forward the VPN port on the router (and nothing else)

On your router's port-forwarding page, add exactly one rule:

| External port | Protocol | Internal IP | Internal port |
|---|---|---|---|
| `JOLE_VPN_PORT` (1194) | `JOLE_VPN_PROTO` (UDP) | `<server LAN IP>` (reserved) | same port |

- **Do not** forward 8443 or any other port to this server.
- Turn **UPnP off**, so no device can open ports on its own.
- If the router already forwards that port to another device, choose another port instead.

## 13. Test from outside

From a device on a **different** network (phone on cellular with Wi-Fi off, or a laptop on a hotspot),
connect the VPN, then reach something on your LAN, for example `ping <LAN host>` or
`ssh <user>@<LAN host>`. On the dashboard the client appears under connected clients.

Testing from inside your own LAN does not prove the router forward works (and many routers do not support
hairpin NAT).

Then run the [verification checks](03-verification.md) and set up [start on boot](04-start-on-boot.md).
