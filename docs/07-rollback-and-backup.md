# Rollback, backup and removal

## Turn off only the admin UI (keep the VPN)

Set this in `.env` and recreate the container:

```ini
JOLE_WEB=0
```

```bash
sudo docker compose up -d
```

The container then behaves exactly like the CLI-only v1: it applies the firewall and runs OpenVPN, with
no web server and nothing published on 8443 inside the container. Manage it with the CLI
(`sudo docker compose run --rm jole-vpn client ...`). Docker still publishes the `WEB_BIND:WEB_PORT`
mapping, but nothing answers on it. Set `JOLE_WEB=1` (or delete the line) to bring the UI back.

## Stop everything

```bash
sudo docker compose down
```

This stops and removes the container. The data volume (CA, clients, config) is **kept**, so
`sudo docker compose up -d` brings everything back as it was. Also remove the router forward if you are
stopping for good.

## Backup

Everything secret lives in the data volume. Back it up and encrypt the archive:

```bash
sudo docker volume ls | grep jole-vpn-data            # exact name, e.g. jole-vpn_gui-suite_jole-vpn-data
sudo docker run --rm -v jole-vpn_gui-suite_jole-vpn-data:/data -v "$PWD":/backup debian:trixie-slim \
  tar czf /backup/jole-vpn-data-$(date +%F).tgz -C /data .
sudo gpg -c jole-vpn-data-*.tgz && sudo shred -u jole-vpn-data-*.tgz
```

Restore by extracting into an empty volume of the same name before starting the container.

## Remove completely

**This destroys the CA and every client certificate.**

```bash
sudo docker compose down --volumes
sudo docker image rm jole-vpn:2.0
```

Then delete the router forward and the folder.
