"""HTTPS admin server for jole-vpn (Python stdlib only)."""
import datetime
import html
import http.cookies
import http.server
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

from . import __version__
from . import auth
from . import commands as C
from . import policy
from . import validate as V
from . import vpnstate as S

MAX_BODY = 64 * 1024
SESSION_COOKIE = "__Host-jvsess"
PRE_COOKIE = "__Host-jvpre"

CSS = """
body{font-family:system-ui,sans-serif;margin:0;background:#f4f6f8;color:#1d2733}
header{background:#1d2733;color:#fff;padding:.6em 1em;display:flex;gap:1em;align-items:center;flex-wrap:wrap}
header a{color:#cfe3ff;text-decoration:none}header b{margin-right:1em}
header form{margin:0 0 0 auto}main{max-width:1000px;margin:1em auto;padding:0 1em}
.card{background:#fff;border-radius:8px;padding:1em 1.2em;margin:0 0 1em;box-shadow:0 1px 3px #0002}
table{border-collapse:collapse;width:100%}td,th{padding:.35em .5em;border-bottom:1px solid #e3e7eb;text-align:left;vertical-align:top}
label{display:block;margin:.5em 0 .15em;font-weight:600}input,select{padding:.35em;font-size:1em;max-width:100%}
input[type=text],input[type=password],input[type=number]{width:22em}
small{color:#5b6672;display:block}button{padding:.4em .9em;font-size:1em;cursor:pointer}
.danger{background:#b3261e;color:#fff;border:0;border-radius:4px}.ok{color:#17702b}.bad{color:#b3261e}
.warn{background:#fff4ce;border-left:4px solid #e0a800;padding:.6em}.secret{font-family:monospace;font-size:1.2em;background:#eef;padding:.3em}
pre{background:#111;color:#ddd;padding:.7em;overflow:auto;white-space:pre-wrap}
.inline{display:inline}fieldset{border:1px solid #d5dbe1;border-radius:6px;margin:.5em 0}
"""

SETUP_HELP = {
    "PUBLIC_HOST": ("Public hostname / DDNS / IP", "What clients connect to from outside, e.g. vpn.example.com"),
    "PORT": ("VPN port", "Must match the router port-forward and JOLE_VPN_PORT in .env"),
    "PROTO": ("Protocol", "udp is best; tcp only if udp is blocked"),
    "SUBNET": ("VPN client subnet", "Must not overlap your LAN, e.g. 10.8.0.0/24"),
    "DNS": ("DNS servers pushed to clients", "Comma-separated. Use your router (e.g. 192.168.1.1) for local names"),
    "CIPHERS": ("Data ciphers", "Colon-separated; keep AES-128-CBC for the M2000"),
    "CERT_TYPE": ("Certificate key type", "ec (fast) / rsa2048 (M2000-safe) / rsa4096"),
    "CERT_DAYS": ("Certificate lifetime (days)", ""),
    "CRL_DAYS": ("CRL lifetime (days)", "Regenerate the CRL before it runs out or ALL clients are refused"),
    "PASSWORD_AUTH": ("Require username + password in addition to the certificate", ""),
    "PASSWORD_MATCH_CN": ("Username must equal the certificate name", ""),
    "TLS_CRYPT": ("tls-crypt (hides/authenticates the control channel)", ""),
    "ROUTING": ("Routing mode", "full = internet + listed LANs; split = only listed LANs via VPN; lan-only = LANs, no internet"),
    "LAN_SUBNETS": ("LAN subnets clients may reach", "Comma-separated, e.g. 192.168.1.0/24 (blank = none)"),
    "MSSFIX": ("Server mssfix", "1360 suits mobile networks"),
}
SETUP_CHOICES = {"PROTO": ("udp", "tcp"), "CERT_TYPE": V.CERT_TYPES, "ROUTING": V.ROUTING_MODES,
                 "PASSWORD_AUTH": ("yes", "no"), "PASSWORD_MATCH_CN": ("yes", "no"), "TLS_CRYPT": ("yes", "no")}

e = html.escape


def log(msg):
    sys.stderr.write("jole-vpn-web: %s\n" % msg)
    sys.stderr.flush()


def fmt_dt(d):
    if not d:
        return "-"
    return d.strftime("%Y-%m-%d %H:%M UTC")


class Ctx:
    """Everything the handler needs; built once at startup (and in tests)."""

    def __init__(self, env=None, paths=None, in_container=None):
        env = dict(os.environ if env is None else env)
        self.env = env
        self.paths = paths or S.Paths(env.get("JOLE_DIR"))
        self.listen, self.bind = policy.check_bind(env, in_container)
        self.port = int(env.get("WEB_LISTEN_PORT") or 8443)
        self.public_port = int(env.get("WEB_PORT") or self.port)
        self.allow_any = policy.yes(env.get("WEB_ALLOW_ANY"))
        self.allow_nets = policy.parse_cidrs(env.get("WEB_ALLOW_CIDRS"))
        self.allow_vpn = policy.yes(env.get("WEB_ALLOW_VPN"))
        self.hostnames = [h for h in (env.get("WEB_HOSTNAMES") or "").split(",") if h.strip()]
        os.makedirs(self.paths.web, mode=0o700, exist_ok=True)
        self.admin = auth.AdminStore(os.path.join(self.paths.web, "admin.json"),
                                     env.get("JOLE_WEB_ADMIN_USER") or "admin", env.get("JOLE_WEB_ADMIN_HASH"))
        self.sessions = auth.Sessions()
        self.pre = auth.PreSessionCsrf()
        self.limiter = auth.RateLimiter()
        self.token = auth.SetupToken()
        self.audit_path = os.path.join(self.paths.web, "audit.log")
        self._audit_lock = threading.Lock()

    def audit(self, ip, user, action, target="", ok=True, note=""):
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "ip": ip, "user": user or "-", "action": action, "target": target, "ok": bool(ok)}
        if note:
            rec["note"] = note
        with self._audit_lock:
            fd = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(rec) + "\n")

    def vpn_subnet(self):
        conf = S.read_conf(self.paths)
        return conf["SUBNET"] if conf else None


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "jole-vpn-web"
    sys_version = ""
    timeout = 30
    ctx = None  # set by make_server

    # ---------- plumbing ----------
    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(15)
            self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):  # access log: method + path only, never query strings or bodies
        pass

    def log_request(self, code="-", size="-"):
        path = urllib.parse.urlsplit(self.path).path
        log("%s %s %s %s" % (self.client_address[0], self.command, path, code))

    def ip(self):
        return self.client_address[0]

    def cookies(self):
        c = http.cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return {}
        return {k: m.value for k, m in c.items()}

    def send_page(self, body, status=200, cookies=(), ctype="text/html; charset=utf-8", extra=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, where, cookies=()):
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()

    @staticmethod
    def cookie(name, value, max_age=None):
        c = "%s=%s; Path=/; Secure; HttpOnly; SameSite=Strict" % (name, value)
        if max_age is not None:
            c += "; Max-Age=%d" % max_age
        return c

    def form(self):
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            raise V.ValidationError("unsupported form encoding")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            raise V.ValidationError("request too large")
        raw = self.rfile.read(n).decode("utf-8", "strict")
        out = {}
        for k, v in urllib.parse.parse_qsl(raw, keep_blank_values=True, max_num_fields=64):
            if k in out:
                raise V.ValidationError("duplicate field %s" % k)
            out[k] = v
        return out

    def gate(self):
        """Source/Host checks applied to every request. Returns True if allowed."""
        ctx = self.ctx
        if not policy.source_allowed(self.ip(), ctx.allow_nets, ctx.vpn_subnet(), ctx.allow_vpn):
            self.send_page(page("Forbidden", "<p>Not allowed from this address.</p>"), 403)
            return False
        if not policy.host_allowed(self.headers.get("Host"), ctx.bind, ctx.hostnames, ctx.allow_any):
            self.send_page(page("Bad host", "<p>Unexpected Host header. Use https://%s:%d/ "
                                "(or add the name to WEB_HOSTNAMES).</p>" % (e(ctx.bind), ctx.public_port)), 421)
            return False
        if self.command == "POST":
            origin = self.headers.get("Origin")
            if origin and origin != "null":
                o = urllib.parse.urlsplit(origin)
                if o.scheme != "https" or not policy.host_allowed(o.netloc, ctx.bind, ctx.hostnames, ctx.allow_any):
                    self.send_page(page("Forbidden", "<p>Cross-origin request refused.</p>"), 403)
                    return False
        return True

    def session(self):
        sid = self.cookies().get(SESSION_COOKIE)
        s = self.ctx.sessions.get(sid)
        if s:
            s["sid"] = sid
        return s

    # ---------- dispatch ----------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.gate():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/static/app.css":
            return self.send_page(CSS, ctype="text/css; charset=utf-8")
        if path == "/healthz":
            return self.send_page("ok\n", ctype="text/plain")
        if not self.ctx.admin.exists():
            return self.get_first_run() if path == "/first-run" else self.redirect("/first-run")
        if path == "/login":
            return self.get_login()
        if path == "/first-run":
            return self.redirect("/login")
        s = self.session()
        if not s:
            return self.redirect("/login")
        route = {"/": self.get_dashboard, "/setup": self.get_setup, "/clients": self.get_clients,
                 "/clients/download": self.get_download, "/audit": self.get_audit,
                 "/account": self.get_account}.get(path)
        if not route:
            return self.send_page(page("Not found", "<p>Not found.</p>", s), 404)
        route(s)

    def do_POST(self):
        if not self.gate():
            return
        path = urllib.parse.urlsplit(self.path).path
        try:
            f = self.form()
        except (V.ValidationError, UnicodeDecodeError, ValueError) as ex:
            return self.send_page(page("Bad request", "<p>%s</p>" % e(str(ex))), 400)
        if path == "/first-run":
            return self.post_first_run(f)
        if path == "/login":
            return self.post_login(f)
        s = self.session()
        if not s:
            return self.redirect("/login")
        if not auth.csrf_ok(s["csrf"], f.get("csrf", "")):
            self.ctx.audit(self.ip(), s["user"], "csrf-reject", path, ok=False)
            return self.send_page(page("Forbidden", "<p>Invalid or missing CSRF token. Reload the page and retry.</p>", s), 403)
        route = {"/logout": self.post_logout, "/setup": self.post_setup, "/clients/add": self.post_client_add,
                 "/clients/revoke": self.post_client_revoke, "/clients/profile": self.post_client_profile,
                 "/clients/profile-all": self.post_profile_all, "/clients/passwd": self.post_client_passwd,
                 "/crl": self.post_crl, "/restart": self.post_restart, "/account": self.post_account}.get(path)
        if not route:
            return self.send_page(page("Not found", "<p>Not found.</p>", s), 404)
        try:
            route(s, f)
        except V.ValidationError as ex:
            self.ctx.audit(self.ip(), s["user"], path.strip("/").replace("/", "-"), "", ok=False, note="validation")
            self.send_page(page("Invalid input", "<p class=bad>%s</p>"
                                "<p>Use your browser's Back button to fix it.</p>" % e(str(ex)), s), 400)

    # ---------- first run / login ----------
    def pre_cookie(self):
        c = self.cookies().get(PRE_COOKIE)
        if c and len(c) < 100:
            return c, []
        c = self.ctx.pre.new_cookie()
        return c, [self.cookie(PRE_COOKIE, c)]

    def get_first_run(self, err=""):
        c, set_c = self.pre_cookie()
        if not self.ctx.token.active:
            tok = self.ctx.token.issue()
            log("FIRST-RUN SETUP TOKEN (one-time, valid until used or restart): %s" % tok)
        body = ("<div class=card><h2>Create the admin account</h2>"
                "<p>Paste the one-time setup token printed in the container log "
                "(<code>docker compose logs jole-vpn | grep TOKEN</code>).</p>%s"
                "<form method=post action=/first-run>%s"
                "<label>Setup token</label><input type=password name=token autocomplete=off required>"
                "<label>Admin username</label><input type=text name=user value=admin required>"
                "<label>Admin password</label><input type=password name=pw autocomplete=new-password minlength=12 required>"
                "<small>At least 12 characters. Store it in your password manager.</small>"
                "<label>Repeat password</label><input type=password name=pw2 autocomplete=new-password required>"
                "<p><button>Create admin</button></p></form></div>") % (
            "<p class=bad>%s</p>" % e(err) if err else "", hidden("pcsrf", self.ctx.pre.token(c)))
        self.send_page(page("First run", body), 200 if not err else 400, set_c)

    def post_first_run(self, f):
        ip = self.ip()
        if self.ctx.admin.exists():
            return self.redirect("/login")
        if not self.ctx.pre.check(self.cookies().get(PRE_COOKIE), f.get("pcsrf")):
            return self.send_page(page("Forbidden", "<p>Invalid CSRF token; reload and retry.</p>"), 403)
        if self.ctx.limiter.blocked(ip):
            self.ctx.audit(ip, None, "first-run", ok=False, note="rate-limited")
            return self.send_page(page("Slow down", "<p>Too many failed attempts. Try again later.</p>"), 429)
        if not self.ctx.token.check(f.get("token", "")):
            self.ctx.limiter.fail(ip)
            self.ctx.audit(ip, None, "first-run", ok=False, note="bad token")
            time.sleep(0.5)
            return self.get_first_run("Wrong or expired setup token (check the newest TOKEN line in the log).")
        try:
            user = V.name(f.get("user"), reserved=())
            pw = V.admin_password(f.get("pw"))
            if pw != f.get("pw2"):
                raise V.ValidationError("passwords do not match")
        except V.ValidationError as ex:
            return self.get_first_run(str(ex))
        self.ctx.admin.set(user, pw)
        self.ctx.token.consume()
        self.ctx.limiter.success(ip)
        self.ctx.audit(ip, user, "first-run", ok=True, note="admin created")
        log("admin account created; setup token invalidated")
        sid = self.ctx.sessions.create(user)
        self.redirect("/", [self.cookie(SESSION_COOKIE, sid)])

    def get_login(self, err="", status=200):
        c, set_c = self.pre_cookie()
        body = ("<div class=card><h2>Sign in</h2>%s<form method=post action=/login>%s"
                "<label>Username</label><input type=text name=user autocomplete=username required>"
                "<label>Password</label><input type=password name=pw autocomplete=current-password required>"
                "<p><button>Sign in</button></p></form></div>") % (
            "<p class=bad>%s</p>" % e(err) if err else "", hidden("pcsrf", self.ctx.pre.token(c)))
        self.send_page(page("Sign in", body), status, set_c)

    def post_login(self, f):
        ip = self.ip()
        if not self.ctx.pre.check(self.cookies().get(PRE_COOKIE), f.get("pcsrf")):
            return self.get_login("Session expired; please try again.", 403)
        if self.ctx.limiter.blocked(ip):
            self.ctx.audit(ip, None, "login", ok=False, note="rate-limited")
            return self.get_login("Too many failed attempts. Wait 15 minutes.", 429)
        user = f.get("user", "")[:64]
        if not self.ctx.admin.check(user, f.get("pw", "")):
            self.ctx.limiter.fail(ip)
            self.ctx.audit(ip, user if V.NAME_RE.match(user) else "?", "login", ok=False)
            time.sleep(0.5)
            return self.get_login("Wrong username or password.", 401)
        self.ctx.limiter.success(ip)
        old = self.cookies().get(SESSION_COOKIE)
        if old:
            self.ctx.sessions.destroy(old)
        sid = self.ctx.sessions.create(user)
        self.ctx.audit(ip, user, "login", ok=True)
        self.redirect("/", [self.cookie(SESSION_COOKIE, sid)])

    def post_logout(self, s, f):
        self.ctx.sessions.destroy(s["sid"])
        self.ctx.audit(self.ip(), s["user"], "logout")
        self.redirect("/login", [self.cookie(SESSION_COOKIE, "x", 0)])

    # ---------- pages ----------
    def get_dashboard(self, s):
        p = self.ctx.paths
        conf = S.read_conf(p)
        parts = []
        if not S.is_configured(p):
            parts.append("<div class='card warn'><b>The VPN is not set up yet.</b> "
                         "<a href=/setup>Run the setup wizard</a>.</div>")
        pid = S.openvpn_pid(p)
        crl = S.crl_info(p)
        rows = [("Version", "jole-vpn %s" % __version__),
                ("OpenVPN", "<span class=ok>running (pid %d)</span>" % pid if pid else "<span class=bad>not running</span>")]
        if conf and S.is_configured(p):
            rows += [("Endpoint", e("%s %s/%s" % (conf["PUBLIC_HOST"], conf["PORT"], conf["PROTO"]))),
                     ("Routing", e("%s; LAN: %s" % (conf["ROUTING"], conf["LAN_SUBNETS"] or "none"))),
                     ("VPN subnet / DNS", e("%s / %s" % (conf["SUBNET"], conf["DNS"]))),
                     ("Auth", "certificate" + (" + password" if conf["PASSWORD_AUTH"] == "yes" else "")
                      + ("; tls-crypt" if conf["TLS_CRYPT"] == "yes" else ""))]
        if crl:
            dl = crl.get("days_left")
            cls = "bad" if dl is not None and dl < 30 else "ok"
            rows.append(("CRL next update", "<span class=%s>%s (%s days)</span>" % (cls, fmt_dt(crl.get("nextUpdate")), dl)))
        parts.append("<div class=card><h2>Status</h2>%s<p>%s %s</p></div>" % (
            table(None, rows),
            post_button("/restart", "Apply config / restart OpenVPN", s),
            post_button("/crl", "Regenerate CRL", s)))
        conn = S.connected_clients(p)
        parts.append("<div class=card><h2>Connected clients (%d)</h2>%s<small>Updated every ~10 s by OpenVPN.</small></div>" % (
            len(conn), table(("Name", "VPN IP", "From", "Since", "Rx", "Tx"),
                             [(e(c["name"]), e(c["vpn_ip"]), e(c["real"]), e(c["since"]), e(c["rx"]), e(c["tx"])) for c in conn])
            if conn else "<p>None.</p>"))
        if crl and crl.get("days_left") is not None and crl["days_left"] < 30:
            parts.insert(0, "<div class='card warn'>The CRL expires in %d days. When it expires OpenVPN refuses "
                            "<b>every</b> client. Click <i>Regenerate CRL</i>.</div>" % crl["days_left"])
        self.send_page(page("Dashboard", "".join(parts), s))

    def get_setup(self, s):
        p = self.ctx.paths
        conf = S.read_conf(p) or dict(S.DEFAULTS)
        configured = S.is_configured(p)
        self.send_page(page("Setup", setup_form(conf, configured, s, os.path.isdir(p.pki)), s))

    def post_setup(self, s, f):
        p = self.ctx.paths
        opts = V.setup_options(f)
        if opts["PROTO"] == "tcp" and int(opts["PORT"]) in (self.ctx.port, self.ctx.public_port):
            raise V.ValidationError("the VPN port may not be the admin UI port")
        configured = S.is_configured(p)
        if configured:
            mode = V.choice(f.get("mode"), ("reconfigure", "rebuild"), "mode")
            if mode == "rebuild" and f.get("confirm") != "REBUILD":
                raise V.ValidationError("type REBUILD to confirm destroying the CA and every client certificate")
        elif os.path.isdir(p.pki):
            # leftover/partial PKI without a complete config: rebuilding wipes it, so confirm
            if f.get("confirm") != "REBUILD":
                raise V.ValidationError("an existing PKI directory was found; type REBUILD to replace it")
            mode = "rebuild"
        else:
            mode = "initial"
        old = S.read_conf(p) or {}
        res = C.run(C.setup_argv(opts, mode))
        self.ctx.audit(self.ip(), s["user"], "setup-" + mode, ok=res.ok,
                       note=",".join(k for k in opts if old.get(k) != opts[k]) or "no changes")
        notes = []
        if res.ok and old and (old.get("PORT"), old.get("PROTO")) != (opts["PORT"], opts["PROTO"]):
            notes.append("Port/protocol changed: set <code>JOLE_VPN_PORT=%s</code> and <code>JOLE_VPN_PROTO=%s</code> "
                         "in <code>.env</code>, update the router port-forward, then run "
                         "<code>docker compose up -d</code> on the host." % (e(opts["PORT"]), e(opts["PROTO"])))
        if res.ok and mode == "reconfigure":
            changed = [k for k in ("PUBLIC_HOST", "PORT", "PROTO", "CIPHERS", "PASSWORD_AUTH", "TLS_CRYPT") if old.get(k) != opts[k]]
            if changed:
                notes.append("Client-facing settings changed (%s): click <i>Regenerate all profiles</i> on the "
                             "Clients page and re-import them on each device." % e(", ".join(changed)))
        if res.ok and mode == "rebuild":
            notes.append("New CA created: every old client profile is now useless. Add clients again.")
        if not res.ok and "PKI exists" in res.output:
            notes.append("An old PKI exists; choose rebuild.")
        body = result_card(res, "Setup (%s)" % mode, notes)
        if res.ok:
            body += "<div class=card>%s <a href=/clients>Go to clients</a></div>" % post_button(
                "/restart", "Apply now (restart OpenVPN)", s)
        self.send_page(page("Setup", body, s), 200 if res.ok else 500)

    def get_clients(self, s):
        p = self.ctx.paths
        conf = S.read_conf(p)
        if not conf or not S.is_configured(p):
            return self.send_page(page("Clients", "<div class=card>Set up the VPN first: <a href=/setup>setup</a>.</div>", s))
        rows = []
        for c in S.list_clients(p, conf.get("SERVER_NAME", "server")):
            n = e(c["name"])
            actions = ""
            if c["status"] == "valid":
                actions = (
                    ("<a href='/clients/download?name=%s'>download .ovpn</a>" % urllib.parse.quote(c["name"])
                     if c["profile"] else "<i>no profile</i>")
                    + "<form method=post action=/clients/profile class=inline>%s%s"
                      "<select name=profile>%s</select><button>regenerate</button></form>" % (
                          csrf(s), hidden("name", c["name"]), options(V.PROFILES, c["profile"] or "mobile"))
                    + ("<form method=post action=/clients/passwd class=inline>%s%s%s<button>new password</button></form>" % (
                        csrf(s), hidden("name", c["name"]), hidden("pwmode", "generate"))
                       if conf["PASSWORD_AUTH"] == "yes" else "")
                    + "<form method=post action=/clients/revoke class=inline>%s%s"
                      "<input type=text name=confirm placeholder='type %s to confirm' size=14>"
                      "<button class=danger>revoke</button></form>" % (csrf(s), hidden("name", c["name"]), n))
            rows.append((n, e(c["status"]), e(c["profile"] or "-"), "yes" if c["password"] else "no",
                         fmt_dt(c["expires"]), actions))
        pw_on = conf["PASSWORD_AUTH"] == "yes"
        add = ("<div class=card><h2>Add a client</h2><form method=post action=/clients/add>%s"
               "<label>Name</label><input type=text name=name required pattern='[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}'>"
               "<small>Letters, digits, . _ - (e.g. alice-phone, m2000). This is also the VPN username.</small>"
               "<label>Profile</label><select name=profile>%s</select>"
               "<small>mobile = phones/laptops (OpenVPN 2.5+); m2000 = Inseego M2000 / OpenVPN 2.4 legacy</small>"
               "%s<p><button>Create client</button></p></form></div>") % (
            csrf(s), options(V.PROFILES, "mobile"),
            ("<fieldset><legend>VPN password</legend>"
             "<label><input type=radio name=pwmode value=generate checked> generate a strong password (shown once)</label>"
             "<label><input type=radio name=pwmode value=set> set my own:</label>"
             "<input type=password name=pw autocomplete=new-password placeholder='min 12 chars'> "
             "<input type=password name=pw2 autocomplete=new-password placeholder='repeat'>"
             "<label><input type=radio name=pwmode value=none> no password (certificate only; this client will fail to "
             "connect while password auth is on)</label></fieldset>") if pw_on else hidden("pwmode", "none"))
        body = add + "<div class=card><h2>Clients</h2>%s<p>%s</p></div>" % (
            table(("Name", "Status", "Profile", "Password", "Expires", "Actions"), rows) if rows else "<p>No clients yet.</p>",
            post_button("/clients/profile-all", "Regenerate all profiles", s))
        self.send_page(page("Clients", body, s))

    def _password_from_form(self, f):
        mode = V.choice(f.get("pwmode", "generate"), ("generate", "set", "none"), "password mode")
        if mode == "set":
            pw = V.vpn_password(f.get("pw"))
            if pw != f.get("pw2"):
                raise V.ValidationError("passwords do not match")
            return mode, pw
        if mode == "generate":
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
            return mode, "".join(secrets.choice(alphabet) for _ in range(24))
        return mode, None

    def post_client_add(self, s, f):
        name = V.name(f.get("name"))
        profile = V.choice(f.get("profile"), V.PROFILES, "profile")
        conf = S.read_conf(self.ctx.paths) or {}
        mode, pw = self._password_from_form(f) if conf.get("PASSWORD_AUTH") == "yes" else ("none", None)
        res = C.run(C.client_add_argv(name, profile, "stdin" if pw else "none"),
                    stdin_text=(pw + "\n") if pw else None)
        self.ctx.audit(self.ip(), s["user"], "client-add", name, res.ok, "profile=%s password=%s" % (profile, mode))
        extra = ""
        if res.ok:
            if mode == "generate":
                extra += ("<div class='card warn'><b>VPN password for %s (shown only now):</b><br>"
                          "<span class=secret>%s</span><br><small>Username: %s. Copy it into the device now; "
                          "it is stored only as a hash.</small></div>") % (e(name), e(pw), e(name))
            extra += "<div class=card><a href='/clients/download?name=%s'>Download %s.ovpn</a> &middot; <a href=/clients>Back</a></div>" % (
                urllib.parse.quote(name), e(name))
        self.send_page(page("Add client", result_card(res, "Add client %s" % name) + extra, s), 200 if res.ok else 500)

    def post_client_revoke(self, s, f):
        name = V.name(f.get("name"))
        if f.get("confirm") != name:
            raise V.ValidationError("type the client name exactly to confirm revocation")
        res = C.run(C.client_revoke_argv(name))
        self.ctx.audit(self.ip(), s["user"], "client-revoke", name, res.ok)
        notes = ["Revoked certificates are refused on their next connection. An already-connected session stays up "
                 "until it reconnects; use <i>Apply / restart</i> to drop it now."] if res.ok else []
        self.send_page(page("Revoke", result_card(res, "Revoke %s" % name, notes) + back("/clients"), s), 200 if res.ok else 500)

    def post_client_profile(self, s, f):
        name = V.name(f.get("name"))
        profile = V.choice(f.get("profile"), V.PROFILES, "profile")
        res = C.run(C.client_profile_argv(name, profile))
        self.ctx.audit(self.ip(), s["user"], "client-profile", name, res.ok, "profile=%s" % profile)
        self.send_page(page("Profile", result_card(res, "Regenerate %s (%s)" % (name, profile)) + back("/clients"), s),
                       200 if res.ok else 500)

    def post_profile_all(self, s, f):
        p = self.ctx.paths
        conf = S.read_conf(p) or {}
        outs, ok = [], True
        for c in S.list_clients(p, conf.get("SERVER_NAME", "server")):
            if c["status"] != "valid":
                continue
            r = C.run(C.client_profile_argv(c["name"], c["profile"] or "mobile"))
            ok = ok and r.ok
            outs.append("%s: %s" % (c["name"], "ok" if r.ok else r.output))
        self.ctx.audit(self.ip(), s["user"], "client-profile-all", "", ok, "count=%d" % len(outs))
        res = C.Result(ok, "\n".join(outs) or "no valid clients")
        self.send_page(page("Profiles", result_card(res, "Regenerate all profiles",
                                                    ["Re-import the new profiles on each device."]) + back("/clients"), s))

    def post_client_passwd(self, s, f):
        name = V.name(f.get("name"))
        mode, pw = self._password_from_form(f)
        if not pw:
            raise V.ValidationError("choose generate or set")
        res = C.run(C.client_passwd_argv(name), stdin_text=pw + "\n")
        self.ctx.audit(self.ip(), s["user"], "client-passwd", name, res.ok, "mode=%s" % mode)
        extra = ""
        if res.ok and mode == "generate":
            extra = ("<div class='card warn'><b>New VPN password for %s (shown only now):</b><br>"
                     "<span class=secret>%s</span></div>") % (e(name), e(pw))
        self.send_page(page("Password", result_card(res, "Password for %s" % name) + extra + back("/clients"), s),
                       200 if res.ok else 500)

    def get_download(self, s):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            name = V.name((q.get("name") or [""])[0])
        except V.ValidationError as ex:
            return self.send_page(page("Bad request", "<p>%s</p>" % e(str(ex)), s), 400)
        path = os.path.join(self.ctx.paths.clients, name + ".ovpn")
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(self.ctx.paths.clients):
            return self.send_page(page("Bad request", "<p>bad path</p>", s), 400)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except FileNotFoundError:
            return self.send_page(page("Not found", "<p>No profile for that client.</p>", s), 404)
        # The download itself is audited (who/which client); the file contents are never logged.
        self.ctx.audit(self.ip(), s["user"], "client-download", name, True)
        self.send_page(data, ctype="application/x-openvpn-profile",
                       extra=[("Content-Disposition", 'attachment; filename="%s.ovpn"' % name)])

    def post_crl(self, s, f):
        res = C.run(C.gen_crl_argv())
        self.ctx.audit(self.ip(), s["user"], "gen-crl", "", res.ok)
        self.send_page(page("CRL", result_card(res, "Regenerate CRL") + back("/"), s), 200 if res.ok else 500)

    def post_restart(self, s, f):
        ok = S.restart_openvpn(self.ctx.paths)
        self.ctx.audit(self.ip(), s["user"], "restart", "", ok)
        msg = ("OpenVPN stopped; the supervisor reloads config + firewall and starts it again within a few seconds. "
               "Connected clients reconnect automatically." if ok else
               "OpenVPN is not running. If setup is complete it starts automatically within ~10 s; "
               "otherwise check <code>docker compose logs jole-vpn</code>.")
        self.send_page(page("Restart", "<div class=card><p>%s</p></div>%s" % (msg, back("/")), s))

    def get_audit(self, s):
        lines = []
        try:
            with open(self.ctx.audit_path) as fh:
                lines = fh.readlines()[-300:]
        except FileNotFoundError:
            pass
        rows = []
        for ln in reversed(lines):
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            rows.append((e(r.get("ts", "")), e(r.get("ip", "")), e(r.get("user", "")), e(r.get("action", "")),
                         e(r.get("target", "")), "ok" if r.get("ok") else "<span class=bad>fail</span>", e(r.get("note", ""))))
        self.send_page(page("Audit log", "<div class=card><h2>Audit log (latest 300)</h2>%s</div>" % table(
            ("Time (UTC)", "From", "User", "Action", "Target", "Result", "Note"), rows), s))

    def get_account(self, s, err="", msg=""):
        body = ("<div class=card><h2>Change admin password</h2>%s%s<form method=post action=/account>%s"
                "<label>Current password</label><input type=password name=cur autocomplete=current-password required>"
                "<label>New password</label><input type=password name=pw autocomplete=new-password minlength=12 required>"
                "<label>Repeat</label><input type=password name=pw2 autocomplete=new-password required>"
                "<p><button>Change password</button></p></form><small>Changing it signs out every other session.</small></div>") % (
            "<p class=bad>%s</p>" % e(err) if err else "", "<p class=ok>%s</p>" % e(msg) if msg else "", csrf(s))
        self.send_page(page("Account", body, s), 400 if err else 200)

    def post_account(self, s, f):
        ip = self.ip()
        if self.ctx.limiter.blocked(ip):
            return self.get_account(s, "Too many failed attempts. Wait 15 minutes.")
        if not self.ctx.admin.check(s["user"], f.get("cur", "")):
            self.ctx.limiter.fail(ip)
            self.ctx.audit(ip, s["user"], "admin-passwd", ok=False)
            return self.get_account(s, "Current password is wrong.")
        try:
            pw = V.admin_password(f.get("pw"))
            if pw != f.get("pw2"):
                raise V.ValidationError("passwords do not match")
        except V.ValidationError as ex:
            return self.get_account(s, str(ex))
        self.ctx.admin.set(s["user"], pw)
        self.ctx.sessions.destroy_all()
        sid = self.ctx.sessions.create(s["user"])
        self.ctx.audit(ip, s["user"], "admin-passwd", ok=True)
        self.send_page(page("Account", "<div class=card><p class=ok>Password changed.</p></div>", None),
                       cookies=[self.cookie(SESSION_COOKIE, sid)])


# ---------- HTML helpers ----------
def hidden(n, v):
    return "<input type=hidden name='%s' value='%s'>" % (e(n), e(v))


def csrf(s):
    return hidden("csrf", s["csrf"])


def post_button(action, label, s, cls=""):
    return "<form method=post action='%s' class=inline>%s<button%s>%s</button></form>" % (
        e(action), csrf(s), " class=%s" % cls if cls else "", e(label))


def options(opts, cur):
    return "".join("<option%s>%s</option>" % (" selected" if o == cur else "", e(o)) for o in opts)


def table(head, rows):
    h = "<tr>%s</tr>" % "".join("<th>%s</th>" % x for x in head) if head else ""
    return "<table>%s%s</table>" % (h, "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r) for r in rows))


def back(href):
    return "<p><a href='%s'>&larr; Back</a></p>" % e(href)


def result_card(res, title, notes=()):
    head = "<span class=ok>done</span>" if res.ok else "<span class=bad>failed</span>"
    n = "".join("<p class=warn>%s</p>" % x for x in notes)
    out = "<pre>%s</pre>" % e(res.output) if res.output else ""
    return "<div class=card><h2>%s: %s</h2>%s%s</div>" % (e(title), head, n, out)


def setup_form(conf, configured, s, pki_exists=False):
    fields = []
    for key, (label, help_) in SETUP_HELP.items():
        val = conf.get(key, "")
        if key in SETUP_CHOICES:
            inp = "<select name=%s>%s</select>" % (key, options(SETUP_CHOICES[key], val))
        else:
            inp = "<input type=text name=%s value='%s'>" % (key, e(val))
        fields.append("<label>%s</label>%s%s" % (e(label), inp, "<small>%s</small>" % e(help_) if help_ else ""))
    if configured:
        mode = ("<fieldset><legend>How to apply</legend>"
                "<label><input type=radio name=mode value=reconfigure checked> Update settings, keep CA and all clients "
                "(recommended)</label><label><input type=radio name=mode value=rebuild> Rebuild everything: NEW CA, "
                "every existing client stops working</label>"
                "<input type=text name=confirm placeholder='type REBUILD for rebuild' autocomplete=off></fieldset>")
        title = "VPN configuration"
    else:
        mode = ("<fieldset class=warn><legend>Existing PKI found</legend>An incomplete earlier setup left a PKI "
                "directory. Saving replaces it. <input type=text name=confirm placeholder='type REBUILD' "
                "autocomplete=off></fieldset>") if pki_exists else ""
        title = "Setup wizard"
    return ("<div class=card><h2>%s</h2><form method=post action=/setup>%s%s%s"
            "<p><button>Save%s</button></p><small>Building a new CA can take a minute (rsa4096: several).</small>"
            "</form></div>") % (title, csrf(s), "".join(fields), mode, "" if configured else " and build the CA")


def page(title, body, s=None):
    nav = ""
    if s:
        nav = ("<a href=/>Dashboard</a><a href=/clients>Clients</a><a href=/setup>Setup / config</a>"
               "<a href=/audit>Audit log</a><a href=/account>Account</a>%s") % post_button("/logout", "Sign out", s)
    return ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width'>"
            "<title>%s - jole-vpn</title><link rel=stylesheet href=/static/app.css></head><body>"
            "<header><b>jole-vpn admin</b>%s</header><main>%s</main></body></html>") % (e(title), nav, body)


# ---------- server ----------
def ensure_tls(ctx):
    d = os.path.join(ctx.paths.web, "tls")
    os.makedirs(d, mode=0o700, exist_ok=True)
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        san = ["DNS:localhost", "IP:127.0.0.1"]
        if ctx.bind not in policy.WILDCARDS:
            san.append("IP:%s" % ctx.bind)
        san += ["DNS:%s" % h.strip() for h in ctx.hostnames if V.HOST_RE.match(h.strip())]
        old = os.umask(0o077)
        try:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-days", "825", "-subj", "/CN=jole-vpn-admin", "-addext",
                            "subjectAltName=" + ",".join(san), "-keyout", key, "-out", cert],
                           check=True, capture_output=True, timeout=60)
        finally:
            os.umask(old)
        log("generated self-signed HTTPS certificate (separate from the VPN CA)")
    fp = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-fingerprint", "-sha256"],
                        capture_output=True, text=True, timeout=20).stdout.strip()
    log("HTTPS certificate %s" % fp)
    return cert, key


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def handle_error(self, request, client_address):
        ex = sys.exc_info()[1]
        if isinstance(ex, (ssl.SSLError, ConnectionError, socket.timeout, TimeoutError)):
            return
        log("error handling request from %s: %s" % (client_address[0], type(ex).__name__))


def make_server(ctx, tls=True):
    cls = type("BoundHandler", (Handler,), {"ctx": ctx})
    family = socket.AF_INET6 if ":" in ctx.listen else socket.AF_INET
    Server.address_family = family
    srv = Server((ctx.listen, ctx.port), cls)
    if tls:
        cert, key = ensure_tls(ctx)
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sc.minimum_version = ssl.TLSVersion.TLSv1_2
        sc.load_cert_chain(cert, key)
        srv.socket = sc.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    return srv


def serve(env=None):
    try:
        ctx = Ctx(env)
    except policy.PolicyError as ex:
        log("refusing to start: %s" % ex)
        return 2
    conf = S.read_conf(ctx.paths)
    if conf and conf["PROTO"] == "tcp" and int(conf["PORT"]) in (ctx.port, ctx.public_port):
        log("refusing to start: admin UI port equals the VPN port")
        return 2
    srv = make_server(ctx)
    if not ctx.admin.exists():
        tok = ctx.token.issue()
        log("no admin account yet. FIRST-RUN SETUP TOKEN (one-time): %s" % tok)
        log("open https://%s:%d/first-run and paste the token" % (ctx.bind, ctx.public_port))
    log("admin UI listening on %s:%d (published on %s:%d)" % (ctx.listen, ctx.port, ctx.bind, ctx.public_port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
