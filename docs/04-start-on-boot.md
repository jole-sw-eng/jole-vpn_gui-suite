# Start on boot

No extra systemd unit is needed. Two things bring the VPN back after a reboot:

1. **The Docker service starts at boot.**

   ```bash
   sudo systemctl enable docker
   systemctl is-enabled docker        # prints: enabled
   ```

2. **The container has a restart policy.** `docker-compose.yml` already contains
   `restart: unless-stopped` for the `jole-vpn` service. Confirm it took effect:

   ```bash
   sudo docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' jole-vpn   # prints: unless-stopped
   ```

   If you use a modified compose file without a `restart:` line, add `restart: unless-stopped` under
   the `jole-vpn` service yourself and run `sudo docker compose up -d`.

## Test it

```bash
sudo reboot
# after it comes back:
sudo docker ps --filter name=jole-vpn
sudo docker compose -f /opt/jole-vpn_gui-suite/docker-compose.yml logs --tail 20 jole-vpn
```

Then open the admin page and connect a client.

## Things to know

- With `unless-stopped`, if you run `sudo docker compose stop` or `down`, the container stays off across
  reboots until you start it again with `sudo docker compose up -d`. That is usually what you want.
- With a LAN bind (`WEB_BIND=<server LAN IP>`), if the server boots with a **different** address, Docker
  cannot publish the admin port and the container does not start. A DHCP reservation (or static IP)
  prevents that.
- After a reboot the UI prints a new first-run token only if no admin account exists yet.
