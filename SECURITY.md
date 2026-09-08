# Security policy

## Intended use

HoneyTrace is designed for authorized security education, isolated labs, and defensive honeypot research. Only run the sensor on systems and networks you own or have explicit permission to test.

The bundled sensor implements SSHv2 transport using AsyncSSH and a pure in-memory terminal. A decoy login grants access only to that terminal. Received commands cannot launch operating-system processes or access host files. File transfers, agent/X11 forwarding, and TCP forwarding are disabled.

## Safe deployment

- Keep the sensor on localhost or a host-only laboratory network by default.
- The dashboard requires a local analyst account. Use HTTPS and a restricted management network for remote access; set HONEYTRACE_HTTPS=true behind an HTTPS reverse proxy so cookies are Secure.
- Use only dummy credentials during demonstrations.
- Treat Cowrie logs and downloaded artifact metadata as potentially sensitive.
- Never commit Cowrie archives, generated databases, credential keys, model artifacts, or environment files.
- Do not execute files or commands recovered from honeypot telemetry.

## Credential handling

HoneyTrace stores a keyed fingerprint, length, entropy, and masked preview for submitted passwords. It does not intentionally retain reusable plaintext credentials. The key is generated locally in `instance/credential.key` and is excluded from version control.

Analyst passwords use Werkzeug scrypt hashes. Login attempts are limited per client IP within the dashboard process; restarting the process resets that limiter. Sessions expire after eight hours and are invalidated when the account password is reset. Mutations require CSRF tokens, and the dashboard uses HttpOnly/SameSite cookies and security headers.

The SSH host key, dashboard signing key, analyst accounts, telemetry, and trained model stay in ignored local directories. The sensor decoy credential is separate from analyst authentication. The default lab-only decoy is root / honeytrace-lab, adjustable using HONEYTRACE_DECOY_PASSWORD. It grants no real system privileges.

Submitted commands may contain secrets or personal data. The evidence viewer and exports are restricted to signed-in analysts; source addresses are masked by default. Do not place sensitive real values in test commands. Exports contain at most 5,000 evidence events and escape spreadsheet formulas.

This release is a lab-oriented implementation, not a production certification. The queue is bounded in memory; abrupt process/OS failure can lose uncommitted events. Heartbeats and dropped-event counters make failures visible. Validate throughput, retention, backups, HTTPS and process supervision for any longer-running deployment.

## Reporting a vulnerability

Please open a GitHub security advisory for the repository instead of publishing credential-handling, code-execution, or data-exposure vulnerabilities in a public issue.
