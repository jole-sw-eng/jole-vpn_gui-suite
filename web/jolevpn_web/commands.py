"""Builds argv lists for the existing jole-vpn scripts and runs them.
Never uses a shell; secrets go over stdin, never argv or logs."""
import os
import subprocess
import threading

from . import validate as V

BIN_DIR = os.environ.get("JOLE_BIN_DIR", "/usr/local/bin")
SETUP = "jole-vpn-setup"
CLIENT = "jole-vpn-client"

SETUP_FLAGS = (
    ("PUBLIC_HOST", "--host"), ("PORT", "--port"), ("PROTO", "--proto"),
    ("SUBNET", "--subnet"), ("DNS", "--dns"), ("CIPHERS", "--ciphers"),
    ("CERT_TYPE", "--cert-type"), ("CERT_DAYS", "--cert-days"),
    ("CRL_DAYS", "--crl-days"), ("PASSWORD_AUTH", "--password-auth"),
    ("PASSWORD_MATCH_CN", "--match-cn"), ("TLS_CRYPT", "--tls-crypt"),
    ("ROUTING", "--routing"), ("LAN_SUBNETS", "--lan"), ("MSSFIX", "--mssfix"),
)

_lock = threading.Lock()  # one PKI-mutating operation at a time


def _bin(name):
    return os.path.join(BIN_DIR, name)


def setup_argv(opts, mode):
    """mode: 'initial' | 'reconfigure' | 'rebuild'. opts must come from validate.setup_options."""
    if mode not in ("initial", "reconfigure", "rebuild"):
        raise V.ValidationError("bad setup mode")
    argv = [_bin(SETUP), "-y"]
    for key, flag in SETUP_FLAGS:
        argv += [flag, opts[key]]
    if mode == "reconfigure":
        argv.append("--reconfigure")
    elif mode == "rebuild":
        argv.append("--force")
    return argv


def client_add_argv(name, profile, password_mode):
    """password_mode: 'stdin' (password sent on stdin) | 'none'."""
    argv = [_bin(CLIENT), "add", V.name(name), "--profile", V.choice(profile, V.PROFILES, "profile")]
    if password_mode == "stdin":
        argv.append("--password-stdin")
    elif password_mode == "none":
        argv.append("--no-password")
    else:
        raise V.ValidationError("bad password mode")
    return argv


def client_profile_argv(name, profile):
    return [_bin(CLIENT), "profile", V.name(name), "--profile", V.choice(profile, V.PROFILES, "profile")]


def client_passwd_argv(name):
    return [_bin(CLIENT), "passwd", V.name(name), "--password-stdin"]


def client_revoke_argv(name):
    return [_bin(CLIENT), "revoke", V.name(name)]


def gen_crl_argv():
    return [_bin(CLIENT), "gen-crl"]


class Result:
    def __init__(self, ok, output):
        self.ok = ok
        self.output = output


def run(argv, stdin_text=None, timeout=900, runner=subprocess.run):
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a list of str")
    env = dict(os.environ, JOLE_NONINTERACTIVE="1")
    with _lock:
        try:
            p = runner(argv, input=(stdin_text if stdin_text is not None else ""),
                       capture_output=True, text=True, timeout=timeout,
                       shell=False, env=env, close_fds=True)
        except subprocess.TimeoutExpired:
            return Result(False, "timed out")
        except OSError as e:
            return Result(False, "could not run %s: %s" % (os.path.basename(argv[0]), e.strerror))
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    return Result(p.returncode == 0, out)
