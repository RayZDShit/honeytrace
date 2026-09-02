# Security policy

## Intended use

HoneyTrace is designed for authorized security education, isolated labs, and defensive honeypot research. Only run the sensor on systems and networks you own or have explicit permission to test.

The bundled sensor is deliberately low interaction. It does not provide real SSH authentication, a shell, a filesystem, command execution, or a successful-login path.

## Safe deployment

- Keep the sensor on localhost or a host-only laboratory network by default.
- Do not expose the dashboard directly to the public Internet. It has no user authentication.
- Use only dummy credentials during demonstrations.
- Treat Cowrie logs and downloaded artifact metadata as potentially sensitive.
- Never commit Cowrie archives, generated databases, credential keys, model artifacts, or environment files.
- Do not execute files or commands recovered from honeypot telemetry.

## Credential handling

HoneyTrace stores a keyed fingerprint, length, entropy, and masked preview for submitted passwords. It does not intentionally retain reusable plaintext credentials. The key is generated locally in `instance/credential.key` and is excluded from version control.

## Reporting a vulnerability

Please open a GitHub security advisory for the repository instead of publishing credential-handling, code-execution, or data-exposure vulnerabilities in a public issue.
