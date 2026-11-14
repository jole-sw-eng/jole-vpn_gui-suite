# Hardening

None of these is required for a working setup, but each one narrows what an attacker can do. Do them in
this order. Settings changes use **reconfigure**, which keeps the CA and every client:

- in the UI: **Setup / config** → change the field → keep *Update settings, keep CA and all clients* → **Save**,
  then **Apply now (restart OpenVPN)**;
- or from the CLI (unset options keep their current values):

  ```bash
  sudo docker compose exec jole-vpn jole-vpn-setup -y --reconfigure <options>
  sudo docker compose restart jole-vpn
  ```

If you change the public host, port, protocol, ciphers, password auth or tls-crypt, regenerate all
profiles (**Clients → Regenerate all profiles**) and re-import them on each device. Routing changes are
pushed by the server, so existing profiles keep working.

## 1. Use lan-only routing with the narrowest subnet

**`lan-only` is the recommended mode for most users.** Only routes to your home-network subnets are
pushed, so only that traffic goes through the tunnel and the device's internet stays direct. The setup
default is `full`, which sends **all** of a client's traffic through your home connection; keep `full`
only if you specifically want that (for example, to protect browsing on untrusted networks). To switch:

```bash
sudo docker compose exec jole-vpn jole-vpn-setup -y --reconfigure --routing lan-only --lan 192.168.1.50/32
sudo docker compose restart jole-vpn
```

Use the smallest range that works: a single `/32` host, several hosts separated by commas, or your
`<LAN subnet>`. With `lan-only` no default route is pushed, so a MiFi hotspot keeps reaching the internet
over its own cellular link and only the listed LAN addresses go through the tunnel; the container
firewall drops anything else that arrives over the VPN. (`split` currently behaves the same.)

## 2. Prefer GCM ciphers

The default `CIPHERS` is `AES-256-GCM:AES-128-GCM:AES-128-CBC`: GCM is tried first, and `AES-128-CBC` is
kept for the Inseego M2000. The `m2000` profile asks for `AES-128-CBC` but also offers GCM via
`ncp-ciphers`, so an M2000 often negotiates GCM anyway.

1. Connect the device and check which cipher it got:

   ```bash
   sudo docker compose logs jole-vpn | grep -i 'data channel'
   ```

2. If every client negotiates GCM, you can remove CBC from the list:

   ```bash
   sudo docker compose exec jole-vpn jole-vpn-setup -y --reconfigure --ciphers AES-256-GCM:AES-128-GCM
   sudo docker compose restart jole-vpn
   ```

   then regenerate and re-import all profiles, and confirm each device still connects. If the M2000 only
   works with CBC, keep the default list. With tls-crypt and `auth SHA256`, CBC is acceptable, if not ideal.

Note: the generated `server.conf` always contains `data-ciphers-fallback AES-128-CBC` (this line is fixed
in `bin/jole-vpn-setup` and is not controlled by `CIPHERS`).

## 3. Keep password auth and tls-crypt on

Leave `PASSWORD_AUTH=yes` (certificate **and** password) and `TLS_CRYPT=yes`. When setting VPN passwords
from the CLI, use the interactive prompt or `--password-stdin`, never `--password PW` (visible in the
process list and shell history); see the [tutorial](02-setup-tutorial.md#10-add-a-client). Consider
`PASSWORD_MATCH_CN=yes` so a password only works with its own certificate. Give each device its own
client, never share one profile between devices, and revoke a lost device immediately:

```bash
sudo docker compose exec jole-vpn jole-vpn-client revoke <name>
```

## CRL renewal

The certificate revocation list expires after `CRL_DAYS` (default **180 days**). When it expires, OpenVPN
refuses **every** client, including ones that were working yesterday.

- Renew it before then, with **Regenerate CRL** on the dashboard, or:

  ```bash
  sudo docker compose exec jole-vpn jole-vpn-client gen-crl
  ```

- The dashboard shows the CRL's next-update date and warns when fewer than 30 days remain.
- Put a recurring reminder in your calendar, about two weeks before each expiry (roughly every 165 days).
  Each renewal starts a new 180-day period.
- Revoking a client also renews the CRL.

## 4. Keep the admin page narrow

- Prefer the loopback bind (`WEB_BIND=127.0.0.1`) and an SSH tunnel.
- With a LAN bind, set `WEB_ALLOW_CIDRS` to the single admin machine (`/32`) rather than the whole LAN.
- Optional backstop on the host, in case a bind is ever wrong: drop UI traffic from outside your LAN
  before it reaches the container (replace the range; the rule is lost on reboot unless you persist it):

  ```bash
  sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8443 ! -s 192.168.1.0/24 -j DROP
  ```

## 5. Housekeeping

- Keep Docker and the host updated; rebuild the image now and then (`sudo docker compose up -d --build`)
  to pick up Debian security updates.
- Back up the data volume, encrypted ([Backup](07-rollback-and-backup.md#backup)).
- If you run more than one VPN entry point on your router, retire the ones you no longer need: each
  forwarded port is attack surface.
