"""Input validation. Mirrors (and is stricter than) the checks in bin/jole-vpn-setup
and bin/jole-vpn-client so that bad input is rejected before any script runs.
Every value that reaches a subprocess argv passes through one of these functions."""
import ipaddress
import re

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
CIPHER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:-]{0,199}$")
CIDR_SHAPE_RE = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")

CERT_TYPES = ("ec", "rsa2048", "rsa4096")
ROUTING_MODES = ("full", "split", "lan-only")
PROFILES = ("mobile", "m2000")
RESERVED_NAMES = ("server",)


class ValidationError(ValueError):
    pass


def name(v, reserved=RESERVED_NAMES):
    v = (v or "").strip()
    if not NAME_RE.match(v):
        raise ValidationError("name must be 1-64 chars: letters, digits, . _ - (not starting with . _ -)")
    if v.lower() in reserved:
        raise ValidationError("name '%s' is reserved" % v)
    return v


def host(v):
    v = (v or "").strip()
    if not v or not HOST_RE.match(v):
        raise ValidationError("public host must be a hostname or IP (letters, digits, . : -)")
    return v


def integer(v, lo, hi, label):
    v = (v or "").strip()
    if not v.isdigit() or not (lo <= int(v) <= hi):
        raise ValidationError("%s must be a whole number %d-%d" % (label, lo, hi))
    return str(int(v))


def port(v):
    return integer(v, 1, 65535, "port")


def proto(v):
    v = (v or "").strip().lower()
    if v not in ("udp", "tcp"):
        raise ValidationError("protocol must be udp or tcp")
    return v


def cidr(v, label="subnet"):
    v = (v or "").strip()
    if not CIDR_SHAPE_RE.match(v):
        raise ValidationError("%s must look like 192.168.1.0/24" % label)
    try:
        net = ipaddress.IPv4Network(v, strict=False)
    except ValueError:
        raise ValidationError("%s is not a valid IPv4 CIDR: %s" % (label, v))
    if net.prefixlen < 8:
        raise ValidationError("%s prefix /%d is too broad" % (label, net.prefixlen))
    return v


def cidr_list(v, label="LAN subnets", allow_empty=True):
    items = [x.strip() for x in (v or "").replace(" ", ",").split(",") if x.strip()]
    if not items and not allow_empty:
        raise ValidationError("%s: at least one CIDR is required" % label)
    if len(items) > 32:
        raise ValidationError("%s: too many entries" % label)
    return ",".join(cidr(x, label) for x in items)


def dns_list(v):
    items = [x.strip() for x in (v or "").replace(" ", ",").split(",") if x.strip()]
    if not items:
        raise ValidationError("at least one DNS server is required")
    if len(items) > 8:
        raise ValidationError("at most 8 DNS servers")
    out = []
    for x in items:
        try:
            ipaddress.ip_address(x)
        except ValueError:
            raise ValidationError("DNS server must be an IP address: %s" % x)
        out.append(x)
    return ",".join(out)


def ciphers(v):
    v = (v or "").strip()
    if not CIPHER_RE.match(v):
        raise ValidationError("ciphers must be colon-separated names, e.g. AES-256-GCM:AES-128-GCM")
    return v


def choice(v, options, label):
    v = (v or "").strip()
    if v not in options:
        raise ValidationError("%s must be one of: %s" % (label, ", ".join(options)))
    return v


def yesno(v):
    v = (v or "").strip().lower()
    if v in ("y", "yes", "on", "true", "1"):
        return "yes"
    if v in ("", "n", "no", "off", "false", "0"):
        return "no"
    raise ValidationError("expected yes/no")


def vpn_password(v):
    if v is None or len(v) < 12:
        raise ValidationError("password must be at least 12 characters")
    if len(v) > 256 or any(c in v for c in "\r\n\x00"):
        raise ValidationError("password may not contain newlines and must be <= 256 chars")
    return v


def admin_password(v):
    if v is None or len(v) < 12:
        raise ValidationError("admin password must be at least 12 characters")
    if len(v) > 1024:
        raise ValidationError("admin password too long")
    return v


def setup_options(form):
    """Validate a full setup/config form. Returns dict of jole-vpn.conf keys."""
    o = {
        "PUBLIC_HOST": host(form.get("PUBLIC_HOST")),
        "PORT": port(form.get("PORT")),
        "PROTO": proto(form.get("PROTO")),
        "SUBNET": cidr(form.get("SUBNET"), "VPN subnet"),
        "DNS": dns_list(form.get("DNS")),
        "CIPHERS": ciphers(form.get("CIPHERS")),
        "CERT_TYPE": choice(form.get("CERT_TYPE"), CERT_TYPES, "cert type"),
        "CERT_DAYS": integer(form.get("CERT_DAYS"), 1, 36500, "cert lifetime"),
        "CRL_DAYS": integer(form.get("CRL_DAYS"), 1, 3650, "CRL lifetime"),
        "PASSWORD_AUTH": yesno(form.get("PASSWORD_AUTH")),
        "PASSWORD_MATCH_CN": yesno(form.get("PASSWORD_MATCH_CN")),
        "TLS_CRYPT": yesno(form.get("TLS_CRYPT")),
        "ROUTING": choice(form.get("ROUTING"), ROUTING_MODES, "routing mode"),
        "LAN_SUBNETS": cidr_list(form.get("LAN_SUBNETS")),
        "MSSFIX": integer(form.get("MSSFIX"), 0, 9000, "mssfix"),
    }
    if o["ROUTING"] != "full" and not o["LAN_SUBNETS"]:
        raise ValidationError("routing '%s' needs at least one LAN subnet" % o["ROUTING"])
    vpn = ipaddress.IPv4Network(o["SUBNET"], strict=False)
    for c in filter(None, o["LAN_SUBNETS"].split(",")):
        if vpn.overlaps(ipaddress.IPv4Network(c, strict=False)):
            raise ValidationError("LAN subnet %s overlaps the VPN subnet %s" % (c, o["SUBNET"]))
    return o
