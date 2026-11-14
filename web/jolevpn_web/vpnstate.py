"""Read-only views of the jole-vpn data directory (config, PKI index, CRL, status)."""
import datetime
import os
import re
import shlex
import signal
import subprocess

from . import validate as V

DEFAULTS = {
    "PUBLIC_HOST": "", "PORT": "1194", "PROTO": "udp", "SUBNET": "10.8.0.0/24",
    "DNS": "1.1.1.1,9.9.9.9", "CIPHERS": "AES-256-GCM:AES-128-GCM:AES-128-CBC",
    "CERT_TYPE": "ec", "CERT_DAYS": "825", "CRL_DAYS": "180", "PASSWORD_AUTH": "yes",
    "PASSWORD_MATCH_CN": "no", "TLS_CRYPT": "yes", "ROUTING": "full", "LAN_SUBNETS": "",
    "MSSFIX": "1360", "SERVER_NAME": "server",
}


class Paths:
    def __init__(self, jole_dir=None):
        self.dir = jole_dir or os.environ.get("JOLE_DIR", "/etc/jole-vpn")
        self.conf = os.path.join(self.dir, "jole-vpn.conf")
        self.server_conf = os.path.join(self.dir, "server.conf")
        self.pki = os.path.join(self.dir, "pki")
        self.index = os.path.join(self.pki, "index.txt")
        self.crl = os.path.join(self.pki, "crl.pem")
        self.clients = os.path.join(self.dir, "clients")
        self.users_db = os.path.join(self.dir, "users.db")
        self.web = os.path.join(self.dir, "web")
        self.status = os.environ.get("JOLE_STATUS_FILE", "/tmp/openvpn-status.log")
        self.pidfile = os.environ.get("JOLE_OVPN_PIDFILE", "/run/jole-vpn/openvpn.pid")


def read_conf(paths):
    """Parse jole-vpn.conf (KEY=value, bash %q quoting). Never sourced/executed."""
    conf = dict(DEFAULTS)
    try:
        with open(paths.conf) as f:
            for line in f:
                line = line.strip()
                m = re.match(r"^([A-Z_]+)=(.*)$", line)
                if not m or m.group(1) not in DEFAULTS:
                    continue
                try:
                    parts = shlex.split(m.group(2), comments=True)
                except ValueError:
                    continue
                conf[m.group(1)] = " ".join(parts)
    except FileNotFoundError:
        return None
    return conf


def is_configured(paths):
    return os.path.isfile(paths.conf) and os.path.isfile(paths.server_conf) and os.path.isfile(os.path.join(paths.pki, "ca.crt"))


def _ts(s):
    # index.txt times: YYMMDDHHMMSSZ (or YYYYMMDDHHMMSSZ)
    try:
        fmt = "%y%m%d%H%M%SZ" if len(s) == 13 else "%Y%m%d%H%M%SZ"
        return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def profile_kind(paths, name):
    try:
        with open(os.path.join(paths.clients, name + ".ovpn")) as f:
            m = re.search(r"\(profile: (mobile|m2000)\)", f.readline())
            return m.group(1) if m else "mobile"
    except FileNotFoundError:
        return None


def password_users(paths):
    users = set()
    try:
        with open(paths.users_db) as f:
            for line in f:
                users.add(line.split(":", 1)[0])
    except (FileNotFoundError, PermissionError):
        pass
    return users


def list_clients(paths, server_name="server"):
    """Latest index.txt entry per CN, server cert excluded."""
    out = {}
    pw = password_users(paths)
    try:
        with open(paths.index) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    for line in lines:
        cols = line.split("\t")
        if len(cols) < 6:
            continue
        st, exp, rev, serial, _fn, dn = cols[:6]
        m = re.search(r"CN=([^/,]+)", dn)
        if not m:
            continue
        cn = m.group(1)
        if cn == server_name or not V.NAME_RE.match(cn):
            continue
        status = {"V": "valid", "R": "revoked", "E": "expired"}.get(st, st)
        expires = _ts(exp)
        if status == "valid" and expires and expires < datetime.datetime.now(datetime.timezone.utc):
            status = "expired"
        entry = {"name": cn, "status": status, "expires": expires, "revoked": _ts(rev.split(",")[0]) if rev else None,
                 "serial": serial, "password": cn in pw, "profile": profile_kind(paths, cn)}
        if cn not in out or status == "valid" or out[cn]["status"] != "valid":
            out[cn] = entry
    return sorted(out.values(), key=lambda e: (e["status"] != "valid", e["name"].lower()))


def crl_info(paths, runner=subprocess.run):
    if not os.path.isfile(paths.crl):
        return None
    try:
        p = runner(["openssl", "crl", "-in", paths.crl, "-noout", "-lastupdate", "-nextupdate"],
                   capture_output=True, text=True, timeout=20, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    info = {}
    for line in p.stdout.splitlines():
        k, _, v = line.partition("=")
        try:
            info[k.strip()] = datetime.datetime.strptime(v.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    nxt = info.get("nextUpdate")
    if nxt:
        info["days_left"] = (nxt - datetime.datetime.now(datetime.timezone.utc)).days
    return info


def parse_status(text):
    """OpenVPN status v1 -> list of connected clients."""
    clients, routes, section = {}, {}, None
    for line in text.splitlines():
        if line.startswith("Common Name,Real Address"):
            section = "clients"; continue
        if line.startswith("ROUTING TABLE"):
            section = None; continue
        if line.startswith("Virtual Address,Common Name"):
            section = "routes"; continue
        if line.startswith("GLOBAL STATS") or line == "END":
            section = None; continue
        cols = line.split(",")
        if section == "clients" and len(cols) >= 5:
            clients[(cols[0], cols[1])] = {"name": cols[0], "real": cols[1], "rx": cols[2], "tx": cols[3],
                                           "since": cols[4], "vpn_ip": ""}
        elif section == "routes" and len(cols) >= 3:
            routes[(cols[1], cols[2])] = cols[0]
    for key, ip in routes.items():
        if key in clients:
            clients[key]["vpn_ip"] = ip
    return list(clients.values())


def connected_clients(paths):
    try:
        with open(paths.status) as f:
            return parse_status(f.read())
    except (FileNotFoundError, PermissionError):
        return []


def openvpn_pid(paths):
    try:
        with open(paths.pidfile) as f:
            pid = int(f.read().strip())
        with open("/proc/%d/comm" % pid) as f:
            if f.read().strip() != "openvpn":
                return None
        return pid
    except (OSError, ValueError):
        return None


def restart_openvpn(paths):
    """Stop OpenVPN; the entrypoint supervisor reloads config + firewall and restarts it."""
    pid = openvpn_pid(paths)
    if not pid:
        return False
    os.kill(pid, signal.SIGTERM)
    return True
