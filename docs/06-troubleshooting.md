# Troubleshooting

Start with the logs:

```bash
sudo docker compose ps
sudo docker compose logs --tail 50 jole-vpn
```

## "Not allowed from this address" (HTTP 403)

The page loaded, so the network path is fine; the app's source-IP check refused you. Causes:

1. **The allowlist does not contain your address.** `WEB_ALLOW_CIDRS` must include the address your
   browser actually comes from. Check it with `ip -4 -br addr` on that machine (use the interface on
   your LAN, not a VPN or Docker interface). The UI's access log shows the source it saw:

   ```bash
   sudo docker compose logs jole-vpn | grep -E ' (GET|POST) ' | tail
   ```

   Fix `.env`, then `sudo docker compose up -d`.
2. **You are browsing from the Docker host itself with an allowlist set.** Requests from the host arrive
   from the Docker bridge (for example `172.17.0.1`). Either browse from another LAN machine, add that
   bridge address to the allowlist, or use the loopback bind with an empty allowlist.
3. **You are coming in over the VPN.** Sources inside the VPN subnet are always refused unless
   `WEB_ALLOW_VPN=yes`. This is intentional: disconnect the VPN and use the LAN.
4. **Your admin machine's DHCP address changed.** Give it a reservation.

## "Unexpected Host header" (HTTP 421)

You used a hostname the guard does not know. Browse by IP (`https://<WEB_BIND>:8443/`, or
`https://127.0.0.1:8443/`), or add the name to `WEB_HOSTNAMES` in `.env` and run
`sudo docker compose up -d`. The HTTPS certificate is created once, so a name added later is not in it;
to regenerate, remove `web/tls/` from the volume and restart.

## The admin page does not load at all / the container keeps restarting

- **`WEB_BIND` is not an address of this host.** Docker cannot publish the port (`cannot assign requested
  address`) and the container does not start. Check `ip -4 -br addr`, fix `WEB_BIND`, run
  `sudo docker compose up -d`. A DHCP reservation for the server prevents this after reboots.
- **`WEB_BIND` is `0.0.0.0` or another wildcard, or not an IP.** The UI logs
  `refusing to start: WEB_BIND must be ...`, and the container stops. Set one specific address.
- **Wrong URL.** It is `https://`, not `http://`, on port `WEB_PORT` (8443).
- **Browsing from another machine with the loopback bind.** Loopback is reachable only on the server;
  use an SSH tunnel or switch to a LAN bind.

## Port already in use

`docker compose up` fails with `address already in use` / `port is already allocated`:

```bash
sudo ss -tulnp | grep -E ':1194|:8443'
```

Stop the other service, or choose another port: set `JOLE_VPN_PORT` (and the same `--port` in setup, and
the router forward) or `WEB_PORT`, then `sudo docker compose up -d`. A TCP VPN port may not equal the UI
port; setup refuses it.

## The first-run token is rejected

Tokens are single-use and a new one is printed on each restart. Use the **newest** `TOKEN` line:

```bash
sudo docker compose logs jole-vpn | grep TOKEN | tail -1
```

Forgot the admin password: `sudo docker compose exec jole-vpn jole-vpn-web reset-admin`, then
`sudo docker compose restart jole-vpn` and use the new token.

## OpenVPN shows "not running"

- Setup not finished: the log says `not configured yet`. Run the wizard.
- `config/firewall failed`: the container needs `NET_ADMIN` and `/dev/net/tun` (both in the compose file).
- See the OpenVPN lines in `sudo docker compose logs jole-vpn`.

## Clients cannot connect

- **Every client fails suddenly**: the CRL probably expired. Run
  `sudo docker compose exec jole-vpn jole-vpn-client gen-crl` ([CRL renewal](05-hardening.md#crl-renewal)).
- **Nothing reaches the server from outside**: check the router forward (port, protocol, the server's
  current IP), that your ISP gives you a public address (no CGNAT), and that `PUBLIC_HOST` resolves to it.
  Test from cellular, not from inside your LAN.
- **AUTH_FAILED**: wrong username/password; the username is the client name. With
  `PASSWORD_MATCH_CN=yes` it must be the same client's certificate.
- **Port/protocol changed** but `.env` not updated: `JOLE_VPN_PORT`/`JOLE_VPN_PROTO` must match setup.
- **M2000 handshake fails**: try `rsa2048`; make sure you used the `m2000` profile.
- **Connected but stalls on cellular**: lower mssfix to 1300.
- **Connected but cannot reach a LAN host**: that host's range must be in `LAN_SUBNETS`
  (all routing modes), and the VPN subnet must not overlap your LAN.
