package io.github.mariaax6.hostbaseline;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Framework-free checks. Run from the project root (build.sh / build.ps1 do this). */
public final class Tests {
    private static int checks;
    private static final Path EXAMPLES = Path.of("examples");

    private static void check(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    private record Result(int code, String out, String err) {}

    private static Result cli(String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(), e = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Result(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    private static void rejects(Path dir, String content, String label) throws IOException {
        Files.writeString(dir.resolve("sshd-effective.txt"), content);
        try { Audit.evaluate(dir, Role.WORKSTATION); throw new AssertionError(label + " (accepted)"); }
        catch (IOException expected) { checks++; }
    }

    private static Finding find(List<Finding> findings, String id) {
        return findings.stream().filter(f -> f.rule().id().equals(id)).findFirst().orElseThrow();
    }

    private static Status statusOf(Path dir, String sshText, String id) throws IOException {
        Files.writeString(dir.resolve("sshd-effective.txt"), sshText);
        return find(Audit.evaluate(dir, Role.WORKSTATION), id).status();
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("hostbaseline-tests-");
        try {
            policyDefinition();
            evaluation(dir);
            parsing(dir);
            numericRules(dir);
            rolesAndExamples();
            escapingAndJson(dir);
            cliBehaviour(dir);
            System.out.println("HostBaseline: " + checks + " checks passed");
        } finally {
            try (var files = Files.walk(dir)) {
                for (Path p : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
            }
        }
    }

    private static void policyDefinition() {
        for (Role role : Role.values()) {
            var rules = Audit.rules(role);
            Set<String> ids = new HashSet<>(), keys = new HashSet<>();
            for (Rule r : rules) { ids.add(r.id()); keys.add(r.source() + ":" + r.key()); }
            check(rules.size() >= 20 && ids.size() == rules.size() && keys.size() == rules.size(), "rule IDs and keys are unique (" + role + ")");
            check(rules.stream().allMatch(r -> r.reference().startsWith("https://") && !r.rationale().isBlank() && !r.remediation().isBlank()),
                    "every rule has rationale, remediation and an https reference");
        }
        check(Audit.rules(Role.WORKSTATION).size() == Audit.rules(Role.ROUTER).size(), "roles share the same rule IDs");
        try { Role.parse("invalid"); throw new AssertionError("invalid role"); } catch (IllegalArgumentException expected) { checks++; }
        check(Role.parse("ROUTER") == Role.ROUTER, "role parsing is case-insensitive");
    }

    private static void evaluation(Path dir) throws IOException {
        var f = Audit.evaluate(dir, Role.WORKSTATION);
        check(f.size() == Audit.rules(Role.WORKSTATION).size() && f.stream().allMatch(x -> x.status() == Status.UNKNOWN), "missing evidence never passes");
        check(f.stream().allMatch(x -> x.observed().equals("not supplied") && x.reason().contains("not supplied")), "missing evidence explains itself");
        f = Audit.evaluate(EXAMPLES.resolve("hardened"), Role.WORKSTATION);
        check(f.stream().allMatch(x -> x.status() == Status.PASS), "hardened example passes everything");
        check(f.stream().allMatch(x -> x.sha256().length() == 64), "SHA-256 evidence on every finding");
        check(Snapshot.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)).equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "SHA-256 known-answer test");
    }

    private static void parsing(Path dir) throws IOException {
        Path ssh = dir.resolve("sshd-effective.txt");
        Files.writeString(ssh, "permitrootlogin no\npermitrootlogin yes\n");
        check(Audit.evaluate(dir, Role.WORKSTATION).get(0).status() == Status.UNKNOWN, "conflicting duplicates are UNKNOWN");
        check(Audit.evaluate(dir, Role.WORKSTATION).get(0).observed().equals("conflicting values"), "conflict is visible in the report value");
        var before = Snapshot.load(ssh, Rule.Source.SSH).sha256();
        Files.writeString(ssh, "PermitRootLogin  NO\npermitrootlogin no\n");
        check(Audit.evaluate(dir, Role.WORKSTATION).get(0).status() == Status.PASS, "identical duplicates, case-insensitive SSH keys and values");
        check(!Snapshot.load(ssh, Rule.Source.SSH).sha256().equals(before), "content change alters evidence hash");
        check(statusOf(dir, "permitrootlogin yes\n", "SSH-01") == Status.FAIL, "explicit policy failure");
        check(statusOf(dir, "loglevel VERBOSE\n", "SSH-12") == Status.PASS, "values are lower-cased (sshd -T prints LogLevel upper-case)");
        check(statusOf(dir, "\uFEFFpermitrootlogin no\n", "SSH-01") == Status.PASS, "UTF-8 BOM tolerated");
        rejects(dir, "Include /etc/ssh/*.conf\n", "raw Include");
        rejects(dir, "Match User example\n", "raw Match");
        rejects(dir, "malformed\n", "malformed line");
        Files.write(ssh, new byte[] {'p', 'e', 'r', 'm', 'i', 't', 'r', 'o', 'o', 't', 'l', 'o', 'g', 'i', 'n', ' ', 'n', 'o', '\n', (byte) 0xFF, (byte) 0xFE, ' ', 'x'});
        try { Audit.evaluate(dir, Role.WORKSTATION); throw new AssertionError("invalid UTF-8 accepted"); }
        catch (IOException expected) { check(expected.getMessage().contains("UTF-8"), "invalid UTF-8 is rejected with a clear message"); }
        Files.write(ssh, "permitrootlogin no\n".getBytes(StandardCharsets.UTF_16));
        try { Audit.evaluate(dir, Role.WORKSTATION); throw new AssertionError("UTF-16 accepted"); }
        catch (IOException expected) { check(expected.getMessage().contains("UTF-16"), "UTF-16 export is detected and explained"); }
        Files.write(ssh, new byte[Snapshot.MAX_BYTES + 1]);
        try { Snapshot.load(ssh, Rule.Source.SSH); throw new AssertionError("oversized snapshot"); } catch (IOException expected) { checks++; }
        Files.delete(ssh);
        Files.createDirectory(ssh);
        try { Audit.evaluate(dir, Role.WORKSTATION); throw new AssertionError("directory accepted as snapshot"); } catch (IOException expected) { checks++; }
        Files.delete(ssh);

        Files.writeString(dir.resolve("sysctl-effective.txt"), "kernel.hotplug =\nnet.ipv4.ip_forward = 0\n");
        check(find(Audit.evaluate(dir, Role.WORKSTATION), "NET-01").status() == Status.PASS, "unrelated empty sysctl value accepted");
        Files.writeString(dir.resolve("sysctl-effective.txt"), "net.ipv4.ip_forward =\n");
        var empty = find(Audit.evaluate(dir, Role.WORKSTATION), "NET-01");
        check(empty.status() == Status.UNKNOWN && empty.reason().equals("empty value"), "empty relevant sysctl value is UNKNOWN");
        Files.writeString(dir.resolve("sysctl-effective.txt"), "net.ipv4.ip_forward = 0\n");
        check(find(Audit.evaluate(dir, Role.WORKSTATION), "NET-02").reason().equals("key not found in snapshot"), "absent key explains itself");
    }

    private static void numericRules(Path dir) throws IOException {
        check(statusOf(dir, "maxauthtries 4\n", "SSH-07") == Status.PASS, "maxauthtries 4 passes");
        check(statusOf(dir, "maxauthtries 5\n", "SSH-07") == Status.FAIL, "maxauthtries 5 fails");
        check(statusOf(dir, "maxauthtries 0\n", "SSH-07") == Status.FAIL, "maxauthtries 0 fails");
        check(statusOf(dir, "maxauthtries abc\n", "SSH-07") == Status.UNKNOWN, "non-numeric maxauthtries is UNKNOWN, not FAIL");
        check(statusOf(dir, "logingracetime 60\n", "SSH-10") == Status.PASS, "logingracetime 60 passes");
        check(statusOf(dir, "logingracetime 120\n", "SSH-10") == Status.FAIL, "logingracetime 120 fails");
        check(statusOf(dir, "logingracetime 0\n", "SSH-10") == Status.FAIL, "logingracetime 0 (unlimited) fails");
    }

    private static void rolesAndExamples() throws IOException {
        var hardenedAsRouter = Audit.evaluate(EXAMPLES.resolve("hardened"), Role.ROUTER);
        check(hardenedAsRouter.stream().filter(x -> x.status() == Status.FAIL).map(x -> x.rule().id()).toList().equals(List.of("NET-01")), "role-specific forwarding policy");
        check(Audit.evaluate(EXAMPLES.resolve("router"), Role.ROUTER).stream().allMatch(x -> x.status() == Status.PASS), "router example passes as router");
        check(Audit.evaluate(EXAMPLES.resolve("router"), Role.WORKSTATION).stream().filter(x -> x.status() == Status.FAIL).count() == 1, "router example fails only NET-01 as workstation");
        var risky = Audit.evaluate(EXAMPLES.resolve("risky"), Role.WORKSTATION);
        check(risky.stream().anyMatch(x -> x.status() == Status.FAIL) && risky.stream().anyMatch(x -> x.status() == Status.PASS), "risky example mixes PASS and FAIL");
        var incomplete = Audit.evaluate(EXAMPLES.resolve("incomplete"), Role.WORKSTATION);
        check(incomplete.stream().filter(x -> x.status() == Status.PASS).count() == 2 && incomplete.stream().filter(x -> x.status() == Status.UNKNOWN).count() == incomplete.size() - 2, "incomplete example is mostly UNKNOWN");
        var drift = Diff.compare(Audit.evaluate(EXAMPLES.resolve("hardened"), Role.WORKSTATION), risky);
        check(Diff.changedCount(drift) > 0 && !drift.get("SSH-01").describe().equals("Unchanged"), "drift detected between hardened and risky");
        check(drift.get("SSH-12").changed() && drift.get("SSH-12").before().status() == drift.get("SSH-12").after().status(), "observed change counts even when both values pass");
        check(!Diff.compare(risky, risky).get("SSH-01").changed(), "identical evaluations show no drift");
    }

    private static void escapingAndJson(Path dir) throws IOException {
        check(Report.quote("\"\\\n\t\u0001").equals("\"\\\"\\\\\\n\\t\\u0001\""), "JSON control characters escaped");
        check(Report.escapeHtml("<img>&\"'").equals("&lt;img&gt;&amp;&quot;&#39;"), "HTML injection escaped");
        Files.writeString(dir.resolve("sshd-effective.txt"), "permitrootlogin <script>alert(\"x\")</script>\n");
        Files.writeString(dir.resolve("sysctl-effective.txt"), "net.ipv4.ip_forward = 0\n");
        var findings = Audit.evaluate(dir, Role.WORKSTATION);
        String html = Report.html(Role.WORKSTATION, "<b>dir</b>", Main.VERSION, findings, null);
        check(!html.contains("<script>") && html.contains("&lt;script&gt;") && html.contains("&lt;b&gt;dir&lt;/b&gt;"), "untrusted values escaped in HTML");
        String json = Report.json(Role.WORKSTATION, Main.VERSION, findings, null);
        Object parsed = new MiniJson(json).parse();
        check(parsed instanceof Map<?, ?> m && m.get("findings") instanceof List<?> l && l.size() == findings.size(), "JSON parses and lists every finding");
        check(json.contains("\\\"x\\\""), "JSON preserves hostile observed values without breaking syntax");
        var withDrift = Report.json(Role.WORKSTATION, Main.VERSION, Audit.evaluate(EXAMPLES.resolve("risky"), Role.WORKSTATION),
                Diff.compare(Audit.evaluate(EXAMPLES.resolve("hardened"), Role.WORKSTATION), Audit.evaluate(EXAMPLES.resolve("risky"), Role.WORKSTATION)));
        new MiniJson(withDrift).parse();
        check(withDrift.contains("\u2192") && json.contains("\"drift\":null") && json.contains("\"changed\":null"), "drift fields reflect whether a baseline was supplied");
    }

    private static void cliBehaviour(Path dir) throws IOException {
        Path reports = dir.resolve("reports");
        var risky = cli("examples/risky", reports.resolve("risky").toString(), "--baseline", "examples/hardened");
        check(risky.code() == 1 && risky.out().contains("FAIL SSH-01".replace("FAIL ", "FAIL    ")) && risky.out().contains("CHANGED="), "risky exits 1, lists failures and reports drift");
        check(Files.isRegularFile(reports.resolve("risky/report.html")) && Files.isRegularFile(reports.resolve("risky/findings.json")), "report files written");
        new MiniJson(Files.readString(reports.resolve("risky/findings.json"))).parse();
        check(cli("examples/hardened", reports.resolve("hardened").toString()).code() == 0, "hardened exits 0");
        var incomplete = cli("examples/incomplete", reports.resolve("incomplete").toString());
        check(incomplete.code() == 3 && incomplete.out().contains("UNKNOWN"), "incomplete exits 3");
        check(cli("examples/router", reports.resolve("r1").toString(), "--role", "router").code() == 0, "router example exits 0 with --role router");
        check(cli("examples/router", reports.resolve("r2").toString()).code() == 1, "router example exits 1 with workstation role");
        Files.writeString(reports.resolve("hardened/report.html"), "stale");
        cli("examples/hardened", reports.resolve("hardened").toString());
        check(Files.readString(reports.resolve("hardened/report.html")).startsWith("<!doctype html>"), "reusing an output directory replaces generated files");

        check(cli("examples/hardened", reports.resolve("x").toString(), "--role", "bogus").code() == 2, "bad role exits 2");
        check(cli("examples/hardened", reports.resolve("x").toString(), "--role").code() == 2, "missing option value exits 2");
        check(cli("examples/hardened", reports.resolve("x").toString(), "--nope").code() == 2, "unknown option exits 2");
        check(cli("examples/hardened").code() == 2 && cli().code() == 2, "wrong argument count exits 2");
        check(cli("does-not-exist", reports.resolve("x").toString()).code() == 2, "absent snapshot directory exits 2");
        check(cli("examples/hardened", reports.resolve("x").toString(), "--baseline", "does-not-exist").code() == 2, "absent baseline directory exits 2");
        Path asFile = Files.writeString(dir.resolve("not-a-dir"), "x");
        check(cli("examples/hardened", asFile.resolve("sub").toString()).code() == 2, "unwritable report directory exits 2");

        check(cli("--help").code() == 0 && cli("--help").out().contains("Usage:"), "--help prints usage");
        var version = cli("--version");
        check(version.code() == 0 && version.out().contains(Main.VERSION), "--version prints version");
        String pom = Files.readString(Path.of("pom.xml"));
        check(pom.contains("<version>" + Main.VERSION + "</version>"), "pom.xml version matches Main.VERSION");
        var list = cli("--list-checks", "--role", "router");
        check(list.code() == 0 && list.out().lines().count() == Audit.rules(Role.ROUTER).size() + 2 && list.out().contains("| NET-01 | medium | sysctl | `net.ipv4.ip_forward` | 1 |"), "--list-checks prints one row per rule");
    }

    /** Minimal strict JSON parser, used only to prove the generated reports are valid JSON. */
    private static final class MiniJson {
        private final String s; private int i;
        MiniJson(String s) { this.s = s; }
        Object parse() {
            Object v = value(); ws();
            if (i != s.length()) throw new AssertionError("trailing JSON data at " + i);
            return v;
        }
        private void ws() { while (i < s.length() && " \n\r\t".indexOf(s.charAt(i)) >= 0) i++; }
        private char peek() { if (i >= s.length()) throw new AssertionError("unexpected end of JSON"); return s.charAt(i); }
        private void expect(char c) { if (peek() != c) throw new AssertionError("expected '" + c + "' at " + i); i++; }
        private Object value() {
            ws();
            char c = peek();
            if (c == '{') { i++; Map<String, Object> m = new java.util.LinkedHashMap<>(); ws();
                if (peek() == '}') { i++; return m; }
                do { ws(); String k = string(); ws(); expect(':'); m.put(k, value()); ws(); } while (s.charAt(i) == ',' && i++ >= 0);
                expect('}'); return m; }
            if (c == '[') { i++; List<Object> l = new ArrayList<>(); ws();
                if (peek() == ']') { i++; return l; }
                do { l.add(value()); ws(); } while (s.charAt(i) == ',' && i++ >= 0);
                expect(']'); return l; }
            if (c == '"') return string();
            for (String lit : new String[] {"true", "false", "null"}) if (s.startsWith(lit, i)) { i += lit.length(); return lit; }
            int start = i; while (i < s.length() && "-+0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            if (start == i) throw new AssertionError("bad JSON value at " + i);
            return Double.valueOf(s.substring(start, i));
        }
        private String string() {
            expect('"'); StringBuilder b = new StringBuilder();
            while (peek() != '"') {
                char c = s.charAt(i++);
                if (c < 32) throw new AssertionError("raw control character in JSON string");
                if (c == '\\') { char e = s.charAt(i++);
                    switch (e) { case '"', '\\', '/' -> b.append(e); case 'n' -> b.append('\n'); case 'r' -> b.append('\r'); case 't' -> b.append('\t'); case 'b' -> b.append('\b'); case 'f' -> b.append('\f');
                        case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                        default -> throw new AssertionError("bad escape"); } }
                else b.append(c);
            }
            i++; return b.toString();
        }
    }
}
