# Verification checks

Run these after the first start and after any change to `.env`, the router or Docker. All are read-only.

## 1. What is listening on the host

```bash
sudo ss -tulnp | grep -E '1194|8443'
```

Expected (default ports):

- `udp ... 0.0.0.0:1194` (and possibly `[::]:1194`): the VPN port, published on all addresses because
  the router forwards it;
- `tcp ... 127.0.0.1:8443` with the loopback bind, **or** `tcp ... <server LAN IP>:8443` with a LAN bind.

**Stop** if 8443 shows `0.0.0.0`, `*` or `[::]`: the admin page would be reachable on every interface.
Run `sudo docker compose down` and fix `WEB_BIND` in `.env`.

## 2. What Docker publishes

```bash
sudo docker port jole-vpn
```

Expected: exactly two mappings, `1194/udp -> 0.0.0.0:1194` (plus an IPv6 line if enabled) and
`8443/tcp -> 127.0.0.1:8443` (or `<server LAN IP>:8443`).

## 3. Docker Engine version

```bash
sudo docker version --format '{{.Server.Version}}'
```

Must be **28.0 or newer** (see the [tutorial](02-setup-tutorial.md#1-install-docker-engine-28-or-newer)).

## 4. Generated server settings

```bash
sudo docker compose exec jole-vpn grep -E '^(tls-crypt|tls-version-min|data-ciphers|auth |crl-verify|user |push)' /etc/jole-vpn/server.conf
sudo docker compose exec jole-vpn grep -E '^(ROUTING|LAN_SUBNETS|TLS_CRYPT|PASSWORD_AUTH|CRL_DAYS)=' /etc/jole-vpn/jole-vpn.conf
sudo docker compose exec jole-vpn jole-vpn-client list
```

Expect `tls-crypt` present, `tls-version-min 1.2`, `auth SHA256`, `crl-verify`, `user nobody`. A
`push "redirect-gateway ..."` line means `full` routing (all client traffic through your network).
The client list should contain only clients you created.

## 5. The admin page is NOT reachable from the internet

1. Find your public IP (your router's status page, or search "what is my IP" from a LAN device).
2. On a phone, **turn Wi-Fi off** so it uses cellular.
3. Open `https://<public IP>:8443/`.

It **must fail** (time out or refuse). If it loads, remove any 8443 forward on the router, turn UPnP off,
and recheck step 1.

## 6. The VPN port is reachable, but silent to strangers

With tls-crypt on, a port scan of `1194/udp` gets no reply; that is expected. The real test is a client
connecting from cellular ([tutorial step 13](02-setup-tutorial.md#13-test-from-outside)).

## 7. VPN clients cannot open the admin page

While connected through the VPN (from outside), open the admin URL. It must be refused
(`Not allowed from this address`) or unreachable. That is by design.

## 8. Router

On the router's port-forward page confirm: one rule for the VPN port to the server's reserved address,
**no** rule for 8443, and UPnP **off**.
