# Security Policy

## Supported Versions

| Version | Supported       |
| ------- | --------------- |
| `main`  | ✅ always latest |
| < 1.0   | ❌ no support    |

Only the **latest release** and the current `main` branch receive security updates. Patch versions are released as needed; minor versions may introduce breaking changes.

---

## Reporting a Vulnerability

If you discover a security issue **please do not create a public GitHub issue**. Instead:

1. Email **[cryptguard737@gmail.com](mailto:cryptguard737@gmail.com)** with the subject `[PASSGEN SECURITY]`.
2. Include a minimal reproduction (PoC) and the affected commit hash / release.
3. If you wish, encrypt your report using our PGP key (`gpg --recv-key 0xDEADBEEF`).

We will acknowledge receipt within **48 hours** and provide a timeline for resolution after triage. Critical issues are usually patched within **72 hours** of confirmation.

---

## Disclosure Process

1. **Confirm & triage** – we reproduce the issue, assess severity (CVSS v4), and assign a CVE if applicable.
2. **Fix development** – patch in a protected branch with unit tests.
3. **Private beta** – send candidate fix to reporter for validation.
4. **Public release** – merge, tag, publish release notes & advisory.
5. **Credit** – reporters are acknowledged in `CHANGELOG.md` unless anonymity is requested.

---

## Out‑of‑scope

* Vulnerabilities exploitable only on devices with root / admin compromise.
* Issues due to the user saving passwords in plain text (feature is disabled by default).
* Missing features (e.g. encrypted vault) are considered enhancements, not vulnerabilities.

---

## Security Practices

* All dependencies are pinned with hashes in `requirements.txt` and regularly checked by Dependabot.
* CI runs `pip-audit` and GitHub Advanced Security code‑scanning.
* Releases are **GPG‑signed**; verify with `git tag -v <tag>`.
* The project follows **SEMVER**; breaking security changes result in a major bump.
