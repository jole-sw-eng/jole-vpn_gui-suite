"""Network exposure policy: where the UI may listen and who may talk to it."""
import ipaddress
import os

WILDCARDS = ("", "0.0.0.0", "::", "*", "[::]")


class PolicyError(RuntimeError):
    pass


def yes(v):
    return (v or "").strip().lower() in ("1", "y", "yes", "true", "on")


def check_bind(env, in_container=None):
    """Validate WEB_BIND / WEB_LISTEN. Returns (listen_addr, bind_addr). Raises PolicyError."""
    if in_container is None:
        in_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    allow_any = yes(env.get("WEB_ALLOW_ANY"))
    bind = (env.get("WEB_BIND") or "").strip()
    listen = (env.get("WEB_LISTEN") or bind).strip()
    if bind in WILDCARDS:
        if not allow_any:
            raise PolicyError("WEB_BIND must be set to one specific LAN address (e.g. 192.168.1.10); "
                              "refusing to expose the admin UI on all interfaces. "
                              "Override only with WEB_ALLOW_ANY=yes.")
    else:
        try:
            ipaddress.ip_address(bind)
        except ValueError:
            raise PolicyError("WEB_BIND must be an IP address, got %r" % bind)
    if listen in WILDCARDS:
        # inside a container 0.0.0.0 is the container's own namespace; docker publishes only on WEB_BIND
        if not (in_container or allow_any):
            raise PolicyError("WEB_LISTEN is a wildcard outside a container; set it to WEB_BIND")
        listen = "0.0.0.0"
    else:
        try:
            ipaddress.ip_address(listen)
        except ValueError:
            raise PolicyError("WEB_LISTEN must be an IP address, got %r" % listen)
    return listen, bind


def parse_cidrs(s):
    nets = []
    for x in (s or "").replace(" ", ",").split(","):
        x = x.strip()
        if x:
            try:
                nets.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                raise PolicyError("bad CIDR in WEB_ALLOW_CIDRS: %r" % x)
    return nets


def source_allowed(ip, allow_nets, vpn_subnet=None, allow_vpn=False):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if vpn_subnet and not allow_vpn:
        try:
            if addr in ipaddress.ip_network(vpn_subnet, strict=False):
                return False
        except ValueError:
            pass
    if allow_nets:
        return any(addr.version == n.version and addr in n for n in allow_nets)
    return True


def host_allowed(host_header, bind, extra_names=(), allow_any=False):
    """DNS-rebinding guard: Host must be the bind address, localhost or a configured name."""
    if allow_any and bind in WILDCARDS:
        return True
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    ok = {"localhost", "127.0.0.1", "::1", (bind or "").lower()} | {n.strip().lower() for n in extra_names if n.strip()}
    return h in ok
