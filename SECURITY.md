# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| < 2.0 | No |

Security fixes are made on the latest 2.x release on `main`.

## Reporting a vulnerability

**Please do not open a public GitHub issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (under *Advisories*).
3. Describe the issue, the affected version or commit, how to reproduce it, and its impact.

Only the maintainers can see the report. You will get a reply in the advisory thread, and a fix and a
GitHub security advisory will be published once the issue is resolved. Credit is given if you want it.

If the **Report a vulnerability** button is not available, open a public issue that says only that you
have a security report and asks for a private contact. Do not include any details in it.

## Scope

In scope: the container image, the scripts in `bin/`, the admin web UI in `web/`, the compose file, and
the documented default configuration.

Out of scope: deployments that ignore the documentation, for example forwarding the admin port (8443)
on a router, binding the UI to `0.0.0.0` with `WEB_ALLOW_ANY=yes`, or `WEB_ALLOW_VPN=yes`.
See [docs/08-security-notes.md](docs/08-security-notes.md).
