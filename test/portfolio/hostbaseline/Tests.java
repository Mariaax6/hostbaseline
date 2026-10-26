package portfolio.hostbaseline;
import java.io.*;
import java.nio.file.*;
import java.util.*;
public final class Tests {
    static int checks;
    static void check(boolean condition,String label) { checks++; if(!condition) throw new AssertionError(label); }
    public static void main(String[] args) throws Exception {
        Path dir=Files.createTempDirectory("hostbaseline-tests-");
        try {
            var f=Audit.evaluate(dir,"workstation");
            check(f.size()==12 && f.stream().allMatch(x->x.status()==Audit.Status.UNKNOWN),"missing evidence never passes");
            Path ssh=dir.resolve("sshd-effective.txt");
            Files.writeString(ssh,"PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\nX11Forwarding no\nMaxAuthTries 4\n");
            Files.writeString(dir.resolve("sysctl-effective.txt"),"net.ipv4.ip_forward = 0\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nkernel.randomize_va_space = 2\n");
            f=Audit.evaluate(dir,"workstation");
            check(f.stream().allMatch(x->x.status()==Audit.Status.PASS),"complete explicit passing snapshot");
            check(Audit.evaluate(dir,"router").stream().filter(x->x.status()==Audit.Status.FAIL).count()==1,"role-specific forwarding policy");
            var snapshot=Audit.load(ssh,true);
            check(snapshot.sha256().length()==64,"SHA256 provenance");
            Files.writeString(ssh,"permitrootlogin no\npermitrootlogin yes\n");
            check(Audit.evaluate(dir,"workstation").get(0).status()==Audit.Status.UNKNOWN,"conflicting duplicate evidence");
            check(!Audit.load(ssh,true).sha256().equals(snapshot.sha256()),"content change alters evidence hash");
            Files.writeString(ssh,"permitrootlogin no\npermitrootlogin no\n");
            check(Audit.evaluate(dir,"workstation").get(0).status()==Audit.Status.PASS,"identical duplicate tolerated");
            Files.writeString(ssh,"permitrootlogin yes\n");
            check(Audit.evaluate(dir,"workstation").get(0).status()==Audit.Status.FAIL,"explicit policy failure");
            Files.writeString(ssh,"Include /etc/ssh/*.conf\n");
            try { Audit.evaluate(dir,"workstation");throw new AssertionError("raw Include accepted"); } catch(IOException expected) { checks++; }
            Files.writeString(ssh,"Match User example\n");
            try { Audit.evaluate(dir,"workstation");throw new AssertionError("raw Match accepted"); } catch(IOException expected) { checks++; }
            Files.writeString(ssh,"malformed\n");
            try { Audit.evaluate(dir,"workstation");throw new AssertionError("malformed accepted"); } catch(IOException expected) { checks++; }
            check(Main.json("\"\\\n\t\u0001").equals("\"\\\"\\\\\\n\\t\\u0001\""),"JSON control characters escaped");
            check(Main.html("<img>&\"").equals("&lt;img&gt;&amp;&quot;"),"HTML injection escaped");
            try { Audit.rules("invalid");throw new AssertionError("invalid role"); } catch(IllegalArgumentException expected) { checks++; }
            Files.writeString(ssh,"permitrootlogin no\n");
            Files.writeString(dir.resolve("sysctl-effective.txt"),"kernel.hotplug =\nnet.ipv4.ip_forward = 0\n");
            check(Audit.evaluate(dir,"workstation").stream().filter(x->x.rule().id().equals("NET-01")).findFirst().orElseThrow().status()==Audit.Status.PASS,"unrelated empty sysctl value accepted");
            Files.writeString(dir.resolve("sysctl-effective.txt"),"net.ipv4.ip_forward =\n");
            check(Audit.evaluate(dir,"workstation").stream().filter(x->x.rule().id().equals("NET-01")).findFirst().orElseThrow().status()==Audit.Status.UNKNOWN,"empty relevant sysctl value unknown");
            Files.write(ssh,new byte[4*1024*1024+1]);
            try { Audit.load(ssh,true);throw new AssertionError("oversized snapshot"); } catch(IOException expected) { checks++; }
            System.out.println("HostBaseline: "+checks+" checks passed");
        } finally { try(var files=Files.walk(dir)) { for(Path p:files.sorted(Comparator.reverseOrder()).toList()) Files.delete(p); } }
    }
}
