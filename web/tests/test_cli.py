"""Backward-compatibility checks for the v1 CLI plus the new --reconfigure / --password-stdin flags."""
import os
import shutil
import subprocess
import tempfile
import unittest

from .test_integration import EASYRSA, REPO_BIN


@unittest.skipUnless(EASYRSA and shutil.which("openssl"), "easy-rsa/openssl not available")
class TestCli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = dict(os.environ, JOLE_DIR=self.d, EASYRSA_BIN=EASYRSA)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_(self, *args, stdin="", ok=True):
        p = subprocess.run([os.path.join(REPO_BIN, args[0])] + list(args[1:]), input=stdin,
                           capture_output=True, text=True, env=self.env, timeout=300)
        if ok:
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            self.assertNotEqual(p.returncode, 0)
        return p

    def test_v1_flow_and_new_flags(self):
        self.run_("jole-vpn-setup", "-y", "--host", "vpn.example.org", "--routing", "lan-only", "--lan", "192.168.1.0/24")
        # v1 behaviour: refuse to clobber PKI without --force
        p = self.run_("jole-vpn-setup", "-y", "--host", "vpn.example.org", ok=False)
        self.assertIn("PKI exists", p.stderr)
        self.run_("jole-vpn-client", "add", "laptop", "--password", "v1-style-password")
        self.run_("jole-vpn-client", "add", "mifi", "--profile", "legacy", "--password-stdin", stdin="stdin-password-123\n")
        with open(os.path.join(self.d, "users.db")) as f:
            db = f.read()
        self.assertIn("mifi:$6$", db)
        self.assertNotIn("stdin-password-123", db)
        out = self.run_("jole-vpn-client", "list").stdout
        self.assertIn("laptop", out)
        self.assertIn("mifi", out)
        self.assertIn("cipher AES-128-CBC", self.run_("jole-vpn-client", "show", "mifi").stdout)
        with open(os.path.join(self.d, "pki", "ca.crt")) as f:
            ca = f.read()
        # reconfigure keeps the CA and unspecified settings
        self.run_("jole-vpn-setup", "-y", "--reconfigure", "--dns", "192.168.1.1")
        with open(os.path.join(self.d, "pki", "ca.crt")) as f:
            self.assertEqual(f.read(), ca)
        with open(os.path.join(self.d, "jole-vpn.conf")) as f:
            conf = f.read()
        self.assertIn("ROUTING=lan-only", conf)
        self.assertIn("DNS=192.168.1.1", conf)
        self.run_("jole-vpn-setup", "-y", "--reconfigure", "--force", ok=False)
        self.run_("jole-vpn-client", "revoke", "laptop")
        self.run_("jole-vpn-client", "gen-crl")
        self.assertRegex(self.run_("jole-vpn-client", "list").stdout, r"laptop\s+revoked")
