# Security Policy

## Supported Versions

NoctisAPI Core is currently maintained as a rolling release.

Security updates are applied to the `main` branch.

There is no guarantee of security support for previous commits or forks.

---

## Reporting a Vulnerability

Do not open public issues for security vulnerabilities.

Report vulnerabilities via:

**abuse@noctisapi.com**

Include:

- Description of the issue
- Steps to reproduce
- Affected components or endpoints
- Potential impact
- Proof of concept (if available)

---

## Response Process

- Initial acknowledgment: within 72 hours
- Triage and validation: based on severity
- Fix timeline: depends on impact and complexity

If accepted:

- Issue is fixed in `main`
- Disclosure may be coordinated

If rejected:

- Reason will be provided

---

## Scope

This policy applies to:

- NoctisAPI Core codebase
- Modular API runtime behavior
- Endpoint definitions and execution logic

Out of scope:

- Misconfiguration of self-hosted deployments
- External infrastructure issues
- Third-party dependencies not controlled by the project

---

## Security Model Note

NoctisAPI Core intentionally simulates vulnerable API behavior as part of its honeypot design.

Reports must distinguish between:

- Intended deceptive behavior
- Unintended security flaws affecting the host system or operator

Only the latter are considered valid vulnerabilities under this policy.
