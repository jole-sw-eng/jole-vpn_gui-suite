"""End-to-end: real HTTPS server + real jole-vpn scripts + easy-rsa, in a temp JOLE_DIR.
Skipped unless easy-rsa is available (set EASYRSA_BIN). Listens on 127.0.0.1 only."""
import http.client
import io
import os
import re
import shutil
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.parse
from contextlib import redirect_stderr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
REPO_BIN = os.path.abspath(os.path.join(HERE, "..", "..", "bin"))

from jolevpn_web import app  # noqa: E402

EASYRSA = os.environ.get("EASYRSA_BIN") or shutil.which("easyrsa") or (
    "/usr/share/easy-rsa/easyrsa" if os.path.exists("/usr/share/easy-rsa/easyrsa") else None)


@unittest.skipUnless(EASYRSA and shutil.which("openssl"), "easy-rsa/openssl not available")
class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["EASYRSA_BIN"] = EASYRSA
        os.environ["JOLE_DIR"] = cls.tmp
        os.environ["JOLE_BIN_DIR"] = REPO_BIN
        from jolevpn_web import commands
        commands.BIN_DIR = REPO_BIN
        env = {"JOLE_DIR": cls.tmp, "WEB_BIND": "127.0.0.1", "WEB_LISTEN_PORT": "0"}
        cls.log = io.StringIO()
        with redirect_stderr(cls.log):
            cls.ctx = app.Ctx(env, in_container=False)
            cls.srv = app.make_server(cls.ctx, tls=True)
            cls.token = cls.ctx.token.issue()
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()
        cls.sslctx = ssl.create_default_context()
        cls.sslctx.check_hostname = False
        cls.sslctx.verify_mode = ssl.CERT_NONE
        cls.cookies = {}

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def req(self, method, path, form=None, host=None, headers=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.sslctx, timeout=600)
        h = {"Host": host or "127.0.0.1:%d" % self.port}
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read().decode("utf-8", "replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, val = v.split(";")[0].split("=", 1)
                self.assertIn("Secure", v)
                self.assertIn("HttpOnly", v)
                self.assertIn("SameSite=Strict", v)
                self.cookies[name] = val
        conn.close()
        return r, data

    def pcsrf(self, html):
        return re.search(r"name='pcsrf' value='([^']+)'", html).group(1)

    def csrf(self, html):
        return re.search(r"name='csrf' value='([^']+)'", html).group(1)

    def test_flow(self):
        # 1. no admin -> first-run; security headers present
        r, d = self.req("GET", "/")
        self.assertEqual(r.status, 303)
        self.assertEqual(r.getheader("Location"), "/first-run")
        r, d = self.req("GET", "/first-run")
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        pc = self.pcsrf(d)
        # DNS-rebinding guard
        r, _ = self.req("GET", "/first-run", host="evil.example")
        self.assertEqual(r.status, 421)
        # wrong token / missing csrf
        r, _ = self.req("POST", "/first-run", {"pcsrf": pc, "token": "nope", "user": "alice",
                                               "pw": "a-long-admin-password", "pw2": "a-long-admin-password"})
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/first-run", {"token": self.token, "user": "alice",
                                               "pw": "a-long-admin-password", "pw2": "a-long-admin-password"})
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/first-run", {"pcsrf": pc, "token": self.token, "user": "alice",
                                               "pw": "a-long-admin-password", "pw2": "a-long-admin-password"},
                        headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/first-run", {"pcsrf": pc, "token": self.token, "user": "alice",
                                               "pw": "a-long-admin-password", "pw2": "a-long-admin-password"})
        self.assertEqual(r.status, 303)
        # token is single-use
        self.assertFalse(self.ctx.token.check(self.token))
        # 2. logout & login again
        r, d = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        r, _ = self.req("POST", "/logout", {"csrf": self.csrf(d)})
        self.assertEqual(r.status, 303)
        r, d = self.req("GET", "/setup")
        self.assertEqual(r.headers["Location"], "/login")
        r, d = self.req("GET", "/login")
        r, d = self.req("POST", "/login", {"pcsrf": self.pcsrf(d), "user": "alice", "pw": "wrong-password-here"})
        self.assertEqual(r.status, 401)
        r, d = self.req("POST", "/login", {"pcsrf": self.pcsrf(d), "user": "alice", "pw": "a-long-admin-password"})
        self.assertEqual(r.status, 303)
        # 3. CSRF required on authenticated POSTs
        r, _ = self.req("POST", "/crl", {})
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/crl", {"csrf": "forged"})
        self.assertEqual(r.status, 403)
        # 4. setup wizard
        r, d = self.req("GET", "/setup")
        self.assertIn("Setup wizard", d)
        tok = self.csrf(d)
        form = {"csrf": tok, "PUBLIC_HOST": "vpn.example.org", "PORT": "1194", "PROTO": "udp",
                "SUBNET": "10.8.0.0/24", "DNS": "192.168.1.1", "CIPHERS": "AES-256-GCM:AES-128-GCM:AES-128-CBC",
                "CERT_TYPE": "ec", "CERT_DAYS": "825", "CRL_DAYS": "180", "PASSWORD_AUTH": "yes",
                "PASSWORD_MATCH_CN": "yes", "TLS_CRYPT": "yes", "ROUTING": "full",
                "LAN_SUBNETS": "192.168.1.0/24", "MSSFIX": "1360"}
        r, d = self.req("POST", "/setup", dict(form, LAN_SUBNETS="192.168.1.0/24;reboot"))
        self.assertEqual(r.status, 400)
        r, d = self.req("POST", "/setup", form)
        self.assertEqual(r.status, 200, d)
        self.assertIn("done", d)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "pki", "ca.crt")))
        with open(os.path.join(self.tmp, "server.conf")) as f:
            sc = f.read()
        self.assertIn('push "route 192.168.1.0 255.255.255.0"', sc)
        self.assertIn('push "dhcp-option DNS 192.168.1.1"', sc)
        ca_path = os.path.join(self.tmp, "pki", "ca.crt")
        with open(ca_path) as f:
            ca_before = f.read()
        # 5. add clients (generated password, legacy profile)
        r, d = self.req("POST", "/clients/add", {"csrf": tok, "name": "alice-phone", "profile": "mobile", "pwmode": "generate"})
        self.assertEqual(r.status, 200, d)
        pw = re.search(r"<span class=secret>([^<]+)</span>", d).group(1)
        self.assertEqual(len(pw), 24)
        r, d = self.req("POST", "/clients/add", {"csrf": tok, "name": "m2000", "profile": "m2000", "pwmode": "set",
                                                 "pw": "my-mifi-password-1", "pw2": "my-mifi-password-1"})
        self.assertEqual(r.status, 200, d)
        r, d = self.req("POST", "/clients/add", {"csrf": tok, "name": "bad name", "profile": "mobile", "pwmode": "none"})
        self.assertEqual(r.status, 400)
        r, d = self.req("GET", "/clients")
        self.assertIn("alice-phone", d)
        self.assertIn("m2000", d)
        # 6. download
        r, d = self.req("GET", "/clients/download?name=m2000")
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        self.assertIn("cipher AES-128-CBC", d)
        self.assertIn("<tls-crypt>", d)
        r, _ = self.req("GET", "/clients/download?name=../server")
        self.assertEqual(r.status, 400)
        # 7. reconfigure keeps CA, change DNS
        r, d = self.req("POST", "/setup", dict(form, DNS="192.168.1.1,1.1.1.1", mode="reconfigure"))
        self.assertEqual(r.status, 200, d)
        with open(ca_path) as f:
            self.assertEqual(f.read(), ca_before)
        with open(os.path.join(self.tmp, "server.conf")) as f:
            self.assertIn("1.1.1.1", f.read())
        # rebuild without confirmation refused
        r, d = self.req("POST", "/setup", dict(form, mode="rebuild"))
        self.assertEqual(r.status, 400)
        # 8. new password, revoke (with confirmation), CRL
        r, d = self.req("POST", "/clients/passwd", {"csrf": tok, "name": "alice-phone", "pwmode": "generate"})
        self.assertEqual(r.status, 200, d)
        r, d = self.req("POST", "/clients/revoke", {"csrf": tok, "name": "alice-phone", "confirm": "nope"})
        self.assertEqual(r.status, 400)
        r, d = self.req("POST", "/clients/revoke", {"csrf": tok, "name": "alice-phone", "confirm": "alice-phone"})
        self.assertEqual(r.status, 200, d)
        r, d = self.req("GET", "/clients")
        self.assertRegex(d, r"alice-phone</td><td>revoked")
        r, d = self.req("POST", "/crl", {"csrf": tok})
        self.assertEqual(r.status, 200, d)
        r, d = self.req("POST", "/clients/profile-all", {"csrf": tok})
        self.assertIn("m2000: ok", d)
        r, d = self.req("GET", "/")
        self.assertIn("CRL next update", d)
        # 9. audit log has actions but never secrets
        with open(os.path.join(self.tmp, "web", "audit.log")) as f:
            audit = f.read()
        for action in ("first-run", "login", "setup-initial", "client-add", "client-download", "client-revoke",
                       "gen-crl", "csrf-reject", "setup-reconfigure"):
            self.assertIn('"%s"' % action, audit)
        for secret in (pw, "my-mifi-password-1", "a-long-admin-password", self.token):
            self.assertNotIn(secret, audit)
        # 10. CLI still works on the same data dir
        import subprocess
        out = subprocess.run([os.path.join(REPO_BIN, "jole-vpn-client"), "list"], capture_output=True, text=True,
                             env=dict(os.environ, JOLE_DIR=self.tmp))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("m2000", out.stdout)

    def test_zz_rate_limit(self):
        ip = "127.0.0.1"
        for _ in range(6):
            self.ctx.limiter.fail(ip)
        r, d = self.req("GET", "/login")
        r, d = self.req("POST", "/login", {"pcsrf": self.pcsrf(d), "user": "alice", "pw": "a-long-admin-password"})
        self.assertEqual(r.status, 429)
        self.ctx.limiter.success(ip)


if __name__ == "__main__":
    unittest.main()
