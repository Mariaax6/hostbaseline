package portfolio.hostbaseline;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Evaluates explicit effective snapshots, never raw sshd_config or live settings. */
public final class Audit {
    public enum Status { PASS, FAIL, UNKNOWN }
    public record Rule(String id,String source,String key,Set<String> expected,String severity,String rationale,String remediation) {}
    public record Finding(Rule rule,Status status,String observed,String evidence) {}
    public record Snapshot(Map<String,String> values,Set<String> ambiguous,String sha256,boolean present) {}
    private static Rule rule(String id,String source,String key,String expected,String severity,String why,String fix) {
        return new Rule(id,source,key,Set.of(expected.split(",")),severity,why,fix);
    }
    public static List<Rule> rules(String role) {
        if(!Set.of("workstation","router").contains(role)) throw new IllegalArgumentException("Role must be workstation or router");
        return List.of(
            rule("SSH-01","ssh","permitrootlogin","no","high","Avoid direct root access","Use an unprivileged account and reviewed sudo permissions before disabling direct root login."),
            rule("SSH-02","ssh","passwordauthentication","no","medium","Prefer managed public-key authentication","Verify working key access and recovery access before disabling password authentication."),
            rule("SSH-03","ssh","kbdinteractiveauthentication","no","medium","Password-free baseline; MFA deployments need a different policy","Review PAM/MFA requirements before disabling keyboard-interactive authentication."),
            rule("SSH-04","ssh","permitemptypasswords","no","high","Reject empty-password logins","Set PermitEmptyPasswords no and verify the effective configuration."),
            rule("SSH-05","ssh","pubkeyauthentication","yes","medium","Require the intended key authentication mechanism","Provision and test public keys before enforcing key-only access."),
            rule("SSH-06","ssh","x11forwarding","no","low","Reduce unnecessary forwarding surface","Disable X11 forwarding unless required for an approved workflow."),
            rule("SSH-07","ssh","maxauthtries","1,2,3,4","low","Limit authentication attempts per connection","Choose MaxAuthTries 4 or lower, considering multi-key clients."),
            rule("NET-01","sysctl","net.ipv4.ip_forward",role.equals("router")?"1":"0","medium","Forwarding depends on host role","Review the host role; forwarding is expected on a router and disabled on this workstation baseline."),
            rule("NET-02","sysctl","net.ipv4.tcp_syncookies","1","medium","Enable SYN-cookie fallback","Review net.ipv4.tcp_syncookies; this is a fallback, not a capacity solution."),
            rule("NET-03","sysctl","net.ipv4.conf.all.accept_source_route","0","medium","Reject IPv4 source routes at the all scope","Review all/default/per-interface source-route policy; this check alone does not cover every interface."),
            rule("NET-04","sysctl","net.ipv4.conf.default.accept_source_route","0","medium","Set safer defaults for new interfaces","Review default and existing interface source-route settings."),
            rule("SYS-01","sysctl","kernel.randomize_va_space","2","medium","Use full address-space randomisation on supported Linux systems","Review kernel.randomize_va_space and application compatibility.")
        );
    }
    public static Snapshot load(Path file,boolean ssh) throws IOException {
        if(!Files.exists(file)) return new Snapshot(Map.of(),Set.of(),"missing",false);
        long size=Files.size(file);
        if(size>4*1024*1024) throw new IOException("Snapshot exceeds 4 MiB: "+file.getFileName());
        byte[] bytes;
        try(InputStream in=Files.newInputStream(file)) { bytes=in.readNBytes(4*1024*1024+1); }
        if(bytes.length>4*1024*1024) throw new IOException("Snapshot grew beyond limit");
        String text=new String(bytes,java.nio.charset.StandardCharsets.UTF_8);
        Map<String,String> values=new HashMap<>(); Set<String> ambiguous=new HashSet<>();
        int lineNo=0;
        for(String raw:text.split("\\R")) {
            lineNo++; String line=raw.strip();
            if(line.isEmpty() || line.startsWith("#")) continue;
            if(ssh && (line.toLowerCase(Locale.ROOT).startsWith("include ") || line.toLowerCase(Locale.ROOT).startsWith("match ")))
                throw new IOException("Raw SSH configuration is not supported. Supply sshd -T output (line "+lineNo+")");
            String[] parts=ssh?line.split("\\s+",2):line.split("\\s*=\\s*",2);
            if(parts.length!=2 || parts[0].isEmpty() || (ssh && parts[1].isBlank())) throw new IOException("Invalid snapshot syntax at "+file.getFileName()+":"+lineNo);
            String key=ssh?parts[0].toLowerCase(Locale.ROOT):parts[0];
            String value=parts[1].strip().toLowerCase(Locale.ROOT);
            String previous=values.putIfAbsent(key,value);
            if(previous!=null && !previous.equals(value)) ambiguous.add(key);
        }
        try { return new Snapshot(Map.copyOf(values),Set.copyOf(ambiguous),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),true); }
        catch(NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    public static List<Finding> evaluate(Path dir,String role) throws IOException {
        Snapshot ssh=load(dir.resolve("sshd-effective.txt"),true), sys=load(dir.resolve("sysctl-effective.txt"),false);
        List<Finding> findings=new ArrayList<>();
        for(Rule r:rules(role)) {
            Snapshot s=r.source().equals("ssh")?ssh:sys;
            String observed=s.values().get(r.key());
            boolean unknown=!s.present() || (observed==null || observed.isBlank()) || s.ambiguous().contains(r.key());
            String evidence=r.source().equals("ssh")?"sshd-effective.txt":"sysctl-effective.txt";
            evidence+="; sha256="+s.sha256();
            if(s.ambiguous().contains(r.key())) evidence+="; conflicting duplicate values";
            findings.add(new Finding(r,unknown?Status.UNKNOWN:r.expected().contains(observed)?Status.PASS:Status.FAIL,observed==null?"not supplied":observed,evidence));
        }
        return List.copyOf(findings);
    }
}
