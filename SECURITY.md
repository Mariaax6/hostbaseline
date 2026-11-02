# Security policy

HostBaseline only reads two text files and writes two report files; it does not connect to hosts or run commands. Even so, snapshot files are treated as **untrusted input** (values are escaped in HTML and JSON, files are size-limited and must be valid UTF-8).

If you find a vulnerability, for example an escaping bypass in a report, please use GitHub's **Report a vulnerability** option on the Security tab of this repository instead of opening a public issue.

Please do not attach real production snapshots to issues; redact hostnames, users and addresses first.
