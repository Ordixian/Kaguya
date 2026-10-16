# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

1. Preferred: use GitHub's private reporting. Go to the repo's **Security** tab, then **Report a vulnerability**.
2. Or email **ordixian@proton.me** with the subject `Kaguya security`.

Include the version (`kaguya status`), your OS, steps to reproduce, and the impact you see.

You can expect an acknowledgement within about 7 days and a fix or mitigation plan once the report is confirmed. Please give us reasonable time to fix before disclosing publicly; we'll credit you in the release notes unless you prefer otherwise.

## Scope notes

Kaguya's dashboard binds to `127.0.0.1` by design and should not be exposed to the internet. Reports about the API accepting writes without the `X-Kaguya-Request` header, Host/Origin check bypasses, command injection in the block-IP action, or unsafe file handling are all in scope.
