"""CLI: python3 -m jolevpn_web serve | hash-password | reset-admin"""
import getpass
import os
import sys

from . import app, auth, validate as V, vpnstate as S


def main(argv):
    cmd = argv[0] if argv else "serve"
    if cmd == "serve":
        return app.serve()
    if cmd == "hash-password":
        pw = getpass.getpass("New admin password (min 12): ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
        if sys.stdin.isatty() and pw != getpass.getpass("Repeat: "):
            print("passwords do not match", file=sys.stderr)
            return 1
        try:
            V.admin_password(pw)
        except V.ValidationError as ex:
            print(ex, file=sys.stderr)
            return 1
        print(auth.hash_password(pw))
        return 0
    if cmd == "reset-admin":
        p = os.path.join(S.Paths().web, "admin.json")
        try:
            os.remove(p)
            print("admin account removed; restart the container and use the new FIRST-RUN token from the log")
        except FileNotFoundError:
            print("no admin account file")
        return 0
    print("usage: jole-vpn-web [serve|hash-password|reset-admin]", file=sys.stderr)
    return 1


sys.exit(main(sys.argv[1:]))
