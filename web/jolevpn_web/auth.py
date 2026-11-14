"""Admin authentication: scrypt hashes, one-time first-run token, sessions, CSRF, rate limiting."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MAXMEM = 64 * 1024 * 1024


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(pw, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=32)
    return "scrypt:%d:%d:%d:%s:%s" % (n, r, p, _b64(salt), _b64(dk))


def verify_password(pw, stored):
    try:
        alg, n, r, p, salt, dk = stored.split(":")
        if alg != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 16):
            return False
        calc = hashlib.scrypt(pw.encode(), salt=_unb64(salt), n=n, r=r, p=p, maxmem=MAXMEM * 4, dklen=len(_unb64(dk)))
        return hmac.compare_digest(calc, _unb64(dk))
    except (ValueError, TypeError):
        return False


_DUMMY = None


def burn_time(pw):
    """Equalise timing for unknown users."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("not-a-real-password")
    verify_password(pw or "", _DUMMY)


class AdminStore:
    """Single admin account stored at <web>/admin.json (0600). Optional env-provided hash."""

    def __init__(self, path, env_user=None, env_hash=None):
        self.path = path
        self.env_user = env_user
        self.env_hash = env_hash
        self._lock = threading.Lock()

    def load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            if isinstance(d, dict) and d.get("user") and str(d.get("hash", "")).startswith("scrypt:"):
                return d
        except (OSError, ValueError):
            pass
        if self.env_user and self.env_hash and self.env_hash.startswith("scrypt:"):
            return {"user": self.env_user, "hash": self.env_hash, "source": "env"}
        return None

    def exists(self):
        return self.load() is not None

    def set(self, user, pw):
        d = {"user": user, "hash": hash_password(pw), "changed": int(time.time())}
        with self._lock:
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(d, f)
            os.replace(tmp, self.path)

    def check(self, user, pw):
        d = self.load()
        if not d or not hmac.compare_digest(str(d["user"]).encode(), (user or "").encode()):
            burn_time(pw)
            return False
        return verify_password(pw or "", d["hash"])


class SetupToken:
    """One-time first-run token. Only its hash is kept; plaintext is printed once to the logs."""

    def __init__(self):
        self._digest = None

    def issue(self):
        tok = secrets.token_urlsafe(24)
        self._digest = hashlib.sha256(tok.encode()).digest()
        return tok

    def check(self, tok):
        if self._digest is None or not tok:
            return False
        return hmac.compare_digest(hashlib.sha256(tok.encode()).digest(), self._digest)

    def consume(self):
        self._digest = None

    @property
    def active(self):
        return self._digest is not None


class Sessions:
    def __init__(self, idle=1800, absolute=12 * 3600, clock=time.time):
        self.idle, self.absolute, self.clock = idle, absolute, clock
        self._s = {}
        self._lock = threading.Lock()

    def create(self, user):
        sid = secrets.token_urlsafe(32)
        now = self.clock()
        with self._lock:
            self._s[sid] = {"user": user, "csrf": secrets.token_urlsafe(32), "created": now, "seen": now}
        return sid

    def get(self, sid):
        if not sid:
            return None
        now = self.clock()
        with self._lock:
            s = self._s.get(sid)
            if not s:
                return None
            if now - s["seen"] > self.idle or now - s["created"] > self.absolute:
                del self._s[sid]
                return None
            s["seen"] = now
            return dict(s)

    def destroy(self, sid):
        with self._lock:
            self._s.pop(sid, None)

    def destroy_all(self):
        with self._lock:
            self._s.clear()


def csrf_ok(expected, given):
    return bool(expected) and bool(given) and hmac.compare_digest(expected.encode(), given.encode())


class PreSessionCsrf:
    """CSRF for forms used before login (login, first-run): token = HMAC(key, pre-session cookie)."""

    def __init__(self, key=None):
        self.key = key or secrets.token_bytes(32)

    def new_cookie(self):
        return secrets.token_urlsafe(24)

    def token(self, cookie):
        return _b64(hmac.new(self.key, cookie.encode(), hashlib.sha256).digest())

    def check(self, cookie, given):
        return bool(cookie) and csrf_ok(self.token(cookie), given or "")


class RateLimiter:
    """Max `limit` failures per `window` seconds per source IP, plus a global cap."""

    def __init__(self, limit=5, window=900, global_limit=30, clock=time.time):
        self.limit, self.window, self.global_limit, self.clock = limit, window, global_limit, clock
        self._f = {}
        self._g = []
        self._lock = threading.Lock()

    def _prune(self, lst, now):
        return [t for t in lst if now - t < self.window]

    def blocked(self, ip):
        now = self.clock()
        with self._lock:
            self._f[ip] = self._prune(self._f.get(ip, []), now)
            self._g = [t for t in self._g if now - t < 60]
            return len(self._f[ip]) >= self.limit or len(self._g) >= self.global_limit

    def fail(self, ip):
        now = self.clock()
        with self._lock:
            self._f.setdefault(ip, []).append(now)
            self._g.append(now)

    def success(self, ip):
        with self._lock:
            self._f.pop(ip, None)
