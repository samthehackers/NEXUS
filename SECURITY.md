# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in NEXUS, please report it
privately rather than opening a public issue:

- Email: **amsamuel6@gmail.com**
- Include: affected version, reproduction steps, and potential impact.

We aim to acknowledge reports within 72 hours and to provide a remediation
timeline within 7 days of confirming a valid issue.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Scope notes

NEXUS processes security-sensitive data (logs, network topology, credential
usage patterns). If you're deploying it:

- Do not expose the FastAPI service (`nexus.api.main`) to the public
  internet without authentication in front of it — v0.1 ships with no
  built-in auth layer.
- Treat topology JSON and log inputs as sensitive; they describe your
  attack surface.
- The `impossible_travel` detector and others are heuristic, not
  cryptographically verified — do not use NEXUS as a sole control for
  access decisions.

## Responsible disclosure

We follow coordinated disclosure. Please give us a reasonable window to
patch before public disclosure of any finding.
