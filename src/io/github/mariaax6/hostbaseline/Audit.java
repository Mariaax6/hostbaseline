package io.github.mariaax6.hostbaseline;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import io.github.mariaax6.hostbaseline.Rule.Matcher;
import io.github.mariaax6.hostbaseline.Rule.Severity;
import io.github.mariaax6.hostbaseline.Rule.Source;

/** Immutable rule definitions and tri-state evaluation of explicit effective snapshots. */
public final class Audit {
    private Audit() {}

    private static final String SSH_DOC = "https://man.openbsd.org/sshd_config.5";
    private static final String NET_DOC = "https://docs.kernel.org/networking/ip-sysctl.html";
    private static final String KERNEL_DOC = "https://docs.kernel.org/admin-guide/sysctl/kernel.html";
    private static final String FS_DOC = "https://docs.kernel.org/admin-guide/sysctl/fs.html";

    private static Rule ssh(String id, String key, Matcher m, Severity sev, String why, String fix) {
        return new Rule(id, Source.SSH, key, m, sev, why, fix, SSH_DOC);
    }

    private static Rule sysctl(String id, String key, Matcher m, Severity sev, String why, String fix, String doc) {
        return new Rule(id, Source.SYSCTL, key, m, sev, why, fix, doc);
    }

    public static List<Rule> rules(Role role) {
        Matcher no = Rule.oneOf("no"), yes = Rule.oneOf("yes"), zero = Rule.oneOf("0"), one = Rule.oneOf("1");
        return List.of(
            ssh("SSH-01", "permitrootlogin", no, Severity.HIGH, "Avoid direct root access",
                "Use an unprivileged account and reviewed sudo permissions before disabling direct root login."),
            ssh("SSH-02", "passwordauthentication", no, Severity.MEDIUM, "Prefer managed public-key authentication",
                "Verify working key access and recovery access before disabling password authentication."),
            ssh("SSH-03", "kbdinteractiveauthentication", no, Severity.MEDIUM,
                "Password-free baseline; MFA deployments need a different policy",
                "Review PAM/MFA requirements before disabling keyboard-interactive authentication."),
            ssh("SSH-04", "permitemptypasswords", no, Severity.HIGH, "Reject empty-password logins",
                "Set PermitEmptyPasswords no and verify the effective configuration."),
            ssh("SSH-05", "pubkeyauthentication", yes, Severity.MEDIUM, "Require the intended key authentication mechanism",
                "Provision and test public keys before enforcing key-only access."),
            ssh("SSH-06", "x11forwarding", no, Severity.LOW, "Reduce unnecessary forwarding surface",
                "Disable X11 forwarding unless required for an approved workflow."),
            ssh("SSH-07", "maxauthtries", new Rule.Range(1, 4), Severity.LOW, "Limit authentication attempts per connection",
                "Choose MaxAuthTries 4 or lower, considering multi-key clients."),
            ssh("SSH-08", "hostbasedauthentication", no, Severity.MEDIUM, "Reject trust based on the connecting host's identity",
                "Set HostbasedAuthentication no unless a reviewed host-trust design requires it."),
            ssh("SSH-09", "permituserenvironment", no, Severity.MEDIUM,
                "Prevent users from injecting environment variables that can bypass restrictions",
                "Set PermitUserEnvironment no and review any workflow that relied on ~/.ssh/environment."),
            ssh("SSH-10", "logingracetime", new Rule.Range(1, 60), Severity.LOW,
                "Limit how long an unauthenticated connection may stay open (0 means no limit)",
                "Choose LoginGraceTime between 1 and 60 seconds; the OpenSSH default is longer."),
            ssh("SSH-11", "allowtcpforwarding", no, Severity.LOW, "Reduce tunnelling surface on hosts that are not jump hosts",
                "Set AllowTcpForwarding no unless bastion or tunnelling use is approved; consider Match blocks for exceptions."),
            ssh("SSH-12", "loglevel", Rule.oneOf("info", "verbose"), Severity.LOW,
                "Keep enough logging to attribute logins; QUIET or FATAL hide authentication events",
                "Use LogLevel INFO or VERBOSE and confirm logs are retained."),
            sysctl("NET-01", "net.ipv4.ip_forward", role == Role.ROUTER ? one : zero, Severity.MEDIUM, "Forwarding depends on host role",
                "Review the host role; forwarding is expected on a router and disabled on this workstation baseline.", NET_DOC),
            sysctl("NET-02", "net.ipv4.tcp_syncookies", one, Severity.MEDIUM, "Enable SYN-cookie fallback",
                "Review net.ipv4.tcp_syncookies; this is a fallback, not a capacity solution.", NET_DOC),
            sysctl("NET-03", "net.ipv4.conf.all.accept_source_route", zero, Severity.MEDIUM, "Reject IPv4 source routes at the all scope",
                "Review all/default/per-interface source-route policy; this check alone does not cover every interface.", NET_DOC),
            sysctl("NET-04", "net.ipv4.conf.default.accept_source_route", zero, Severity.MEDIUM, "Set safer defaults for new interfaces",
                "Review default and existing interface source-route settings.", NET_DOC),
            sysctl("NET-05", "net.ipv4.conf.all.rp_filter", Rule.oneOf("1", "2"), Severity.MEDIUM,
                "Reverse-path filtering drops packets with spoofed source addresses (2 = loose mode, used with asymmetric routing)",
                "Set rp_filter to 1 (strict) or 2 (loose) after checking for asymmetric routing.", NET_DOC),
            sysctl("NET-06", "net.ipv4.conf.all.accept_redirects", zero, Severity.MEDIUM, "Ignore ICMP redirects that can alter routing",
                "Review accept_redirects at all/default/per-interface scope.", NET_DOC),
            sysctl("NET-07", "net.ipv4.icmp_echo_ignore_broadcasts", one, Severity.LOW, "Do not answer broadcast echo requests",
                "Set net.ipv4.icmp_echo_ignore_broadcasts to 1.", NET_DOC),
            sysctl("SYS-01", "kernel.randomize_va_space", Rule.oneOf("2"), Severity.MEDIUM,
                "Use full address-space randomisation on supported Linux systems",
                "Review kernel.randomize_va_space and application compatibility.", KERNEL_DOC),
            sysctl("SYS-02", "kernel.kptr_restrict", Rule.oneOf("1", "2"), Severity.LOW, "Hide kernel pointers from unprivileged users",
                "Set kernel.kptr_restrict to 1 or 2.", KERNEL_DOC),
            sysctl("SYS-03", "kernel.dmesg_restrict", one, Severity.LOW, "Restrict kernel log access to privileged users",
                "Set kernel.dmesg_restrict to 1 after checking monitoring agents that read dmesg.", KERNEL_DOC),
            sysctl("SYS-04", "fs.protected_symlinks", one, Severity.LOW, "Mitigate symlink races in world-writable sticky directories",
                "Set fs.protected_symlinks to 1.", FS_DOC),
            sysctl("SYS-05", "fs.protected_hardlinks", one, Severity.LOW, "Prevent hardlinks to files the user cannot read or write",
                "Set fs.protected_hardlinks to 1.", FS_DOC));
    }

    public static List<Finding> evaluate(Path dir, Role role) throws IOException {
        Snapshot ssh = Snapshot.load(dir.resolve(Source.SSH.fileName()), Source.SSH);
        Snapshot sys = Snapshot.load(dir.resolve(Source.SYSCTL.fileName()), Source.SYSCTL);
        List<Finding> findings = new ArrayList<>();
        for (Rule r : rules(role)) {
            Snapshot s = r.source() == Source.SSH ? ssh : sys;
            String observed = s.values().get(r.key());
            Status status;
            String reason = "";
            String shown = observed;
            if (!s.present()) {
                status = Status.UNKNOWN; reason = "snapshot file not supplied"; shown = null;
            } else if (s.ambiguous().contains(r.key())) {
                status = Status.UNKNOWN; reason = "conflicting duplicate values"; shown = "conflicting values";
            } else if (observed == null) {
                status = Status.UNKNOWN; reason = "key not found in snapshot";
            } else if (observed.isBlank()) {
                status = Status.UNKNOWN; reason = "empty value";
            } else {
                status = r.matcher().test(observed);
                if (status == Status.UNKNOWN) reason = "value could not be interpreted";
            }
            findings.add(new Finding(r, status, shown == null ? "not supplied" : shown, reason, r.source().fileName(), s.sha256()));
        }
        return List.copyOf(findings);
    }
}
