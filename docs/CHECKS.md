# Checks

Generated with `java -jar dist/hostbaseline.jar --list-checks`. Expected values shown are for the **workstation** role; with `--role router`, NET-01 expects `1`. Each check's rationale, remediation and reference appear in `findings.json` and the HTML report.

| ID | Severity | Source | Key | Expected (workstation) |
|---|---|---|---|---|
| SSH-01 | high | ssh | `permitrootlogin` | no |
| SSH-02 | medium | ssh | `passwordauthentication` | no |
| SSH-03 | medium | ssh | `kbdinteractiveauthentication` | no |
| SSH-04 | high | ssh | `permitemptypasswords` | no |
| SSH-05 | medium | ssh | `pubkeyauthentication` | yes |
| SSH-06 | low | ssh | `x11forwarding` | no |
| SSH-07 | low | ssh | `maxauthtries` | between 1 and 4 |
| SSH-08 | medium | ssh | `hostbasedauthentication` | no |
| SSH-09 | medium | ssh | `permituserenvironment` | no |
| SSH-10 | low | ssh | `logingracetime` | between 1 and 60 |
| SSH-11 | low | ssh | `allowtcpforwarding` | no |
| SSH-12 | low | ssh | `loglevel` | info or verbose |
| NET-01 | medium | sysctl | `net.ipv4.ip_forward` | 0 |
| NET-02 | medium | sysctl | `net.ipv4.tcp_syncookies` | 1 |
| NET-03 | medium | sysctl | `net.ipv4.conf.all.accept_source_route` | 0 |
| NET-04 | medium | sysctl | `net.ipv4.conf.default.accept_source_route` | 0 |
| NET-05 | medium | sysctl | `net.ipv4.conf.all.rp_filter` | 1 or 2 |
| NET-06 | medium | sysctl | `net.ipv4.conf.all.accept_redirects` | 0 |
| NET-07 | low | sysctl | `net.ipv4.icmp_echo_ignore_broadcasts` | 1 |
| SYS-01 | medium | sysctl | `kernel.randomize_va_space` | 2 |
| SYS-02 | low | sysctl | `kernel.kptr_restrict` | 1 or 2 |
| SYS-03 | low | sysctl | `kernel.dmesg_restrict` | 1 |
| SYS-04 | low | sysctl | `fs.protected_symlinks` | 1 |
| SYS-05 | low | sysctl | `fs.protected_hardlinks` | 1 |
