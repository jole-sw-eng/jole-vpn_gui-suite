import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from jolevpn_web import auth, commands as C, policy, validate as V, vpnstate as S  # noqa: E402

GOOD = {"PUBLIC_HOST": "vpn.example.org", "PORT": "1194", "PROTO": "udp", "SUBNET": "10.8.0.0/24",
        "DNS": "192.168.1.1, 1.1.1.1", "CIPHERS": "AES-256-GCM:AES-128-GCM:AES-128-CBC", "CERT_TYPE": "rsa2048",
        "CERT_DAYS": "825", "CRL_DAYS": "180", "PASSWORD_AUTH": "yes", "PASSWORD_MATCH_CN": "yes",
        "TLS_CRYPT": "yes", "ROUTING": "full", "LAN_SUBNETS": "192.168.1.0/24", "MSSFIX": "1360"}


class TestValidate(unittest.TestCase):
    def test_names(self):
        for ok in ("phone", "alice-phone", "m2000", "A.b_c-1", "x" * 64):
            self.assertEqual(V.name(ok), ok)
        for bad in ("", "-rf", ".hidden", "_x", "a b", "a/b", "../etc", "a;rm", "$(id)", "x" * 65, "ñ", "a\nb",
                    "server", "SERVER", "--profile"):
            with self.assertRaises(V.ValidationError, msg=bad):
                V.name(bad)

    def test_cidr(self):
        self.assertEqual(V.cidr("192.168.1.0/24"), "192.168.1.0/24")
        for bad in ("192.168.1.0", "300.1.1.1/24", "192.168.1.0/33", "0.0.0.0/0", "10.0.0.0/7", "::/0", "a.b.c.d/24",
                    "192.168.1.0/24;x", " -1.2.3.4/24"):
            with self.assertRaises(V.ValidationError, msg=bad):
                V.cidr(bad)
        self.assertEqual(V.cidr_list("192.168.1.0/24, 10.20.0.0/16"), "192.168.1.0/24,10.20.0.0/16")
        self.assertEqual(V.cidr_list(""), "")

    def test_host_dns_ciphers(self):
        self.assertEqual(V.host("vpn.example.com"), "vpn.example.com")
        for bad in ("", "-x", "a b", "a;b", "a$(b)", "x" * 300):
            with self.assertRaises(V.ValidationError):
                V.host(bad)
        self.assertEqual(V.dns_list("192.168.1.1,1.1.1.1"), "192.168.1.1,1.1.1.1")
        for bad in ("", "dns.google", "1.1.1.1;x"):
            with self.assertRaises(V.ValidationError):
                V.dns_list(bad)
        for bad in ("AES 256", "-AES", "AES;x"):
            with self.assertRaises(V.ValidationError):
                V.ciphers(bad)

    def test_setup_options(self):
        o = V.setup_options(GOOD)
        self.assertEqual(o["DNS"], "192.168.1.1,1.1.1.1")
        self.assertEqual(o["PASSWORD_AUTH"], "yes")
        bad = dict(GOOD, ROUTING="split", LAN_SUBNETS="")
        with self.assertRaises(V.ValidationError):
            V.setup_options(bad)
        with self.assertRaises(V.ValidationError):
            V.setup_options(dict(GOOD, LAN_SUBNETS="10.8.0.0/16"))  # overlaps VPN subnet
        for k, v in (("PORT", "0"), ("PORT", "70000"), ("PROTO", "icmp"), ("CERT_TYPE", "dsa"),
                     ("ROUTING", "all"), ("MSSFIX", "abc"), ("PASSWORD_AUTH", "maybe"), ("CERT_DAYS", "-1")):
            with self.assertRaises(V.ValidationError, msg=k):
                V.setup_options(dict(GOOD, **{k: v}))

    def test_passwords(self):
        with self.assertRaises(V.ValidationError):
            V.vpn_password("short")
        with self.assertRaises(V.ValidationError):
            V.vpn_password("longenough-but\nnewline")
        self.assertEqual(V.vpn_password("a" * 12), "a" * 12)


class TestCommands(unittest.TestCase):
    def test_setup_argv(self):
        o = V.setup_options(GOOD)
        argv = C.setup_argv(o, "initial")
        self.assertTrue(argv[0].endswith("jole-vpn-setup"))
        self.assertIn("-y", argv)
        self.assertNotIn("--force", argv)
        self.assertEqual(argv[argv.index("--lan") + 1], "192.168.1.0/24")
        self.assertEqual(argv[argv.index("--routing") + 1], "full")
        self.assertIn("--reconfigure", C.setup_argv(o, "reconfigure"))
        self.assertIn("--force", C.setup_argv(o, "rebuild"))
        with self.assertRaises(V.ValidationError):
            C.setup_argv(o, "nuke")
        for a in argv[1:]:
            self.assertIsInstance(a, str)

    def test_client_argv(self):
        a = C.client_add_argv("phone", "m2000", "stdin")
        self.assertEqual(a[1:], ["add", "phone", "--profile", "m2000", "--password-stdin"])
        self.assertEqual(C.client_add_argv("x", "mobile", "none")[-1], "--no-password")
        self.assertEqual(C.client_revoke_argv("phone")[1:], ["revoke", "phone"])
        self.assertEqual(C.client_passwd_argv("phone")[1:], ["passwd", "phone", "--password-stdin"])
        for bad in ("--force", "a b", "$(reboot)", "server"):
            with self.assertRaises(V.ValidationError):
                C.client_add_argv(bad, "mobile", "none")
        with self.assertRaises(V.ValidationError):
            C.client_add_argv("ok", "evil", "none")

    def test_run_no_shell_secret_on_stdin(self):
        seen = {}

        def fake(argv, **kw):
            seen.update(kw, argv=argv)

            class P:
                returncode, stdout, stderr = 0, "out", ""
            return P()
        r = C.run(C.client_add_argv("phone", "mobile", "stdin"), stdin_text="S3cret-password-xyz\n", runner=fake)
        self.assertTrue(r.ok)
        self.assertIs(seen["shell"], False)
        self.assertEqual(seen["input"], "S3cret-password-xyz\n")
        self.assertNotIn("S3cret-password-xyz", " ".join(seen["argv"]))
        self.assertEqual(seen["env"]["JOLE_NONINTERACTIVE"], "1")
        with self.assertRaises(TypeError):
            C.run("jole-vpn-client list", runner=fake)


class TestAuth(unittest.TestCase):
    def test_hash(self):
        h = auth.hash_password("correct horse battery", n=2 ** 14)
        self.assertTrue(h.startswith("scrypt:16384:8:1:"))
        self.assertTrue(auth.verify_password("correct horse battery", h))
        self.assertFalse(auth.verify_password("correct horse batterY", h))
        self.assertFalse(auth.verify_password("x", "garbage"))
        self.assertFalse(auth.verify_password("x", "scrypt:2:8:1:AA:AA"))  # too-weak params refused
        self.assertNotEqual(h, auth.hash_password("correct horse battery", n=2 ** 14))  # salted

    def test_admin_store(self):
        with tempfile.TemporaryDirectory() as d:
            st = auth.AdminStore(os.path.join(d, "admin.json"))
            self.assertFalse(st.exists())
            st.set("alice", "a-long-admin-password")
            self.assertEqual(os.stat(os.path.join(d, "admin.json")).st_mode & 0o777, 0o600)
            self.assertTrue(st.check("alice", "a-long-admin-password"))
            self.assertFalse(st.check("admin", "a-long-admin-password"))
            self.assertFalse(st.check("alice", "wrong"))
            with open(os.path.join(d, "admin.json")) as f:
                self.assertNotIn("a-long-admin-password", f.read())
            env_st = auth.AdminStore(os.path.join(d, "none.json"), "ops", auth.hash_password("env-provided-pass", n=2 ** 14))
            self.assertTrue(env_st.check("ops", "env-provided-pass"))

    def test_token(self):
        t = auth.SetupToken()
        self.assertFalse(t.check("x"))
        tok = t.issue()
        self.assertFalse(t.check(tok + "x"))
        self.assertTrue(t.check(tok))
        t.consume()
        self.assertFalse(t.check(tok))

    def test_sessions(self):
        now = [1000.0]
        s = auth.Sessions(idle=60, absolute=300, clock=lambda: now[0])
        sid = s.create("alice")
        self.assertEqual(s.get(sid)["user"], "alice")
        self.assertGreaterEqual(len(s.get(sid)["csrf"]), 40)
        now[0] += 59
        self.assertIsNotNone(s.get(sid))
        now[0] += 61
        self.assertIsNone(s.get(sid))  # idle timeout
        sid = s.create("alice")
        for _ in range(10):
            now[0] += 50
            s.get(sid)
        self.assertIsNone(s.get(sid))  # absolute timeout
        self.assertIsNone(s.get("forged"))

    def test_csrf(self):
        self.assertTrue(auth.csrf_ok("abc", "abc"))
        self.assertFalse(auth.csrf_ok("abc", ""))
        self.assertFalse(auth.csrf_ok("", ""))
        self.assertFalse(auth.csrf_ok("abc", "abd"))
        p = auth.PreSessionCsrf()
        c = p.new_cookie()
        self.assertTrue(p.check(c, p.token(c)))
        self.assertFalse(p.check(c, p.token("other")))
        self.assertFalse(p.check(None, p.token(c)))
        self.assertFalse(auth.PreSessionCsrf().check(c, p.token(c)))  # different server key

    def test_rate_limit(self):
        now = [0.0]
        rl = auth.RateLimiter(limit=5, window=900, global_limit=30, clock=lambda: now[0])
        for _ in range(4):
            rl.fail("192.168.1.20")
        self.assertFalse(rl.blocked("192.168.1.20"))
        rl.fail("192.168.1.20")
        self.assertTrue(rl.blocked("192.168.1.20"))
        self.assertFalse(rl.blocked("192.168.1.21"))
        now[0] += 901
        self.assertFalse(rl.blocked("192.168.1.20"))
        for i in range(30):
            rl.fail("10.0.0.%d" % i)
        self.assertTrue(rl.blocked("192.168.1.99"))  # global cap


class TestPolicy(unittest.TestCase):
    def test_bind(self):
        with self.assertRaises(policy.PolicyError):
            policy.check_bind({}, in_container=True)
        with self.assertRaises(policy.PolicyError):
            policy.check_bind({"WEB_BIND": "0.0.0.0"}, in_container=True)
        with self.assertRaises(policy.PolicyError):
            policy.check_bind({"WEB_BIND": "myhost"}, in_container=True)
        self.assertEqual(policy.check_bind({"WEB_BIND": "192.168.1.10"}, False), ("192.168.1.10", "192.168.1.10"))
        self.assertEqual(policy.check_bind({"WEB_BIND": "192.168.1.10", "WEB_LISTEN": "0.0.0.0"}, True),
                         ("0.0.0.0", "192.168.1.10"))
        with self.assertRaises(policy.PolicyError):  # wildcard listen on a bare host
            policy.check_bind({"WEB_BIND": "192.168.1.10", "WEB_LISTEN": "0.0.0.0"}, False)
        self.assertEqual(policy.check_bind({"WEB_BIND": "0.0.0.0", "WEB_ALLOW_ANY": "yes"}, False)[0], "0.0.0.0")

    def test_source(self):
        nets = policy.parse_cidrs("192.168.1.0/24")
        self.assertTrue(policy.source_allowed("192.168.1.20", nets, "10.8.0.0/24"))
        self.assertFalse(policy.source_allowed("192.168.5.20", nets, "10.8.0.0/24"))
        self.assertFalse(policy.source_allowed("10.8.0.2", [], "10.8.0.0/24"))  # VPN clients blocked by default
        self.assertTrue(policy.source_allowed("10.8.0.2", [], "10.8.0.0/24", allow_vpn=True))
        self.assertFalse(policy.source_allowed("::ffff:10.8.0.2", [], "10.8.0.0/24"))
        self.assertTrue(policy.source_allowed("172.17.0.1", [], None))
        self.assertFalse(policy.source_allowed("garbage", [], None))
        with self.assertRaises(policy.PolicyError):
            policy.parse_cidrs("nope")

    def test_host(self):
        self.assertTrue(policy.host_allowed("192.168.1.10:8443", "192.168.1.10"))
        self.assertTrue(policy.host_allowed("localhost:8443", "192.168.1.10"))
        self.assertTrue(policy.host_allowed("server.lan", "192.168.1.10", ["server.lan"]))
        self.assertFalse(policy.host_allowed("evil.example:8443", "192.168.1.10"))
        self.assertFalse(policy.host_allowed(None, "192.168.1.10"))


class TestState(unittest.TestCase):
    def test_conf_and_index(self):
        with tempfile.TemporaryDirectory() as d:
            p = S.Paths(d)
            os.makedirs(p.pki)
            os.makedirs(p.clients)
            with open(p.conf, "w") as f:
                f.write("# x\nPUBLIC_HOST=vpn.example.org\nLAN_SUBNETS=192.168.1.0/24\nDNS=''\nEVIL=$(id)\n"
                        "ROUTING=lan-only   # comment\n")
            c = S.read_conf(p)
            self.assertEqual(c["PUBLIC_HOST"], "vpn.example.org")
            self.assertEqual(c["DNS"], "")
            self.assertEqual(c["ROUTING"], "lan-only")
            self.assertNotIn("EVIL", c)
            with open(p.index, "w") as f:
                f.write("V\t290211160137Z\t\tAA\tunknown\t/CN=server\n"
                        "R\t290211160137Z\t251101000000Z,unspecified\tBB\tunknown\t/CN=old\n"
                        "V\t290211160137Z\t\tCC\tunknown\t/CN=phone\n"
                        "V\t200101000000Z\t\tDD\tunknown\t/CN=stale\n")
            with open(os.path.join(p.clients, "phone.ovpn"), "w") as f:
                f.write("# jole-vpn client: phone (profile: m2000)\n")
            with open(p.users_db, "w") as f:
                f.write("phone:$6$x$y\n")
            cl = {x["name"]: x for x in S.list_clients(p)}
            self.assertNotIn("server", cl)
            self.assertEqual(cl["phone"]["status"], "valid")
            self.assertEqual(cl["phone"]["profile"], "m2000")
            self.assertTrue(cl["phone"]["password"])
            self.assertEqual(cl["old"]["status"], "revoked")
            self.assertEqual(cl["stale"]["status"], "expired")

    def test_status(self):
        txt = ("OpenVPN CLIENT LIST\nUpdated,2026-11-09 10:00:00\n"
               "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
               "phone,203.0.113.5:4242,1000,2000,2026-11-09 09:00:00\nROUTING TABLE\n"
               "Virtual Address,Common Name,Real Address,Last Ref\n10.8.0.2,phone,203.0.113.5:4242,2026-11-09 10:00:00\n"
               "GLOBAL STATS\nMax bcast/mcast queue length,0\nEND\n")
        c = S.parse_status(txt)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["vpn_ip"], "10.8.0.2")
        self.assertEqual(S.parse_status(""), [])


if __name__ == "__main__":
    unittest.main()
