## HostBaseline 2.0.0

Major revision. **Breaking changes:** command-line syntax, JSON schema and Java package name.

- 24 checks (was 12): five new SSH checks (host-based auth, user environment, login grace time, TCP forwarding, log level), and new network and kernel hardening checks.
- Numeric rules (`MaxAuthTries`, `LoginGraceTime`) are compared as numbers; a non-numeric value is now UNKNOWN instead of FAIL.
- Snapshots must be valid UTF-8. Malformed input and UTF-16 exports (e.g. PowerShell `>`) are rejected with a clear message instead of being silently repaired.
- Named options: `--role`, `--baseline`, `--list-checks`, `--version`.
- Findings now carry the reason for UNKNOWN, a reference link and structured evidence. JSON `schemaVersion` is 2.
- HTML report supports dark mode; console output lists every failing or unknown check.
- New router example, `demo.sh`, end-to-end exit-code verification in CI, Dependabot for workflow updates and a SHA-256 checksum published with the JAR.

Requires a Java 17+ runtime. This is an educational tool; see the README for unsupported formats, policy assumptions and interpretation limits.
