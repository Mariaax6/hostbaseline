package io.github.mariaax6.hostbaseline;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import io.github.mariaax6.hostbaseline.Diff.Drift;

/** Renders findings as a self-contained HTML page and as machine-readable JSON. */
public final class Report {
    private Report() {}

    public record Summary(int pass, int fail, int unknown, Long changed) {}

    public static Summary summarize(List<Finding> findings, Map<String, Drift> drift) {
        int pass = 0, fail = 0, unknown = 0;
        for (Finding f : findings) {
            switch (f.status()) { case PASS -> pass++; case FAIL -> fail++; case UNKNOWN -> unknown++; }
        }
        return new Summary(pass, fail, unknown, drift == null ? null : Diff.changedCount(drift));
    }

    static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String quote(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 32) out.append(String.format("\\u%04x", (int) c)); else out.append(c); }
            }
        }
        return out.append('"').toString();
    }

    /** Pass {@code drift} as null when no baseline was supplied. */
    public static String json(Role role, String version, List<Finding> findings, Map<String, Drift> drift) {
        Summary s = summarize(findings, drift);
        StringBuilder out = new StringBuilder();
        out.append("{\"schemaVersion\":2,\"tool\":\"hostbaseline\",\"version\":").append(quote(version))
           .append(",\"role\":").append(quote(role.id()))
           .append(",\"summary\":{\"pass\":").append(s.pass()).append(",\"fail\":").append(s.fail())
           .append(",\"unknown\":").append(s.unknown()).append(",\"changed\":").append(s.changed() == null ? "null" : s.changed())
           .append("},\n\"findings\":[\n");
        boolean first = true;
        for (Finding f : findings) {
            Rule r = f.rule();
            Drift d = drift == null ? null : drift.get(r.id());
            if (!first) out.append(",\n");
            first = false;
            out.append("{\"id\":").append(quote(r.id()))
               .append(",\"key\":").append(quote(r.key()))
               .append(",\"source\":").append(quote(r.source().id()))
               .append(",\"status\":").append(quote(f.status().name()))
               .append(",\"severity\":").append(quote(r.severity().id()))
               .append(",\"observed\":").append(quote(f.observed()))
               .append(",\"expected\":").append(quote(r.matcher().describe()))
               .append(",\"reason\":").append(quote(f.reason()))
               .append(",\"evidence\":{\"file\":").append(quote(f.file())).append(",\"sha256\":").append(quote(f.sha256())).append('}')
               .append(",\"rationale\":").append(quote(r.rationale()))
               .append(",\"remediation\":").append(quote(r.remediation()))
               .append(",\"reference\":").append(quote(r.reference()))
               .append(",\"drift\":").append(d == null ? "null" : quote(d.describe())).append('}');
        }
        return out.append("\n]}\n").toString();
    }

    private static final String CSS = """
        :root{--bg:#f0f3f8;--fg:#16283e;--card:#fff;--line:#d6e0ea;--muted:#53657b;--code:#edf2f7;--hero:#142c45;--pass:#147148;--fail:#ac2836;--unknown:#876010}
        @media (prefers-color-scheme:dark){:root{--bg:#0f1824;--fg:#e3eaf3;--card:#17283b;--line:#2a4058;--muted:#9fb2c6;--code:#223850;--hero:#0a2238;--pass:#4cc38a;--fail:#ff7a85;--unknown:#e6b455}}
        body{font:16px/1.6 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0}
        main{max-width:1100px;margin:45px auto;padding:0 24px}
        h1{font-size:46px;margin:0}h3{margin:12px 0 4px}
        .eyebrow{color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase;margin:0}
        .metrics{display:flex;gap:32px;flex-wrap:wrap;background:var(--hero);color:#fff;padding:26px;border-radius:14px;margin:28px 0}
        .metrics b{display:block;font-size:32px}
        article{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:18px 0;padding:24px}
        header{display:flex;gap:16px;align-items:center}
        .badge{font-weight:700}.PASS{color:var(--pass)}.FAIL{color:var(--fail)}.UNKNOWN{color:var(--unknown)}
        small,footer,.meta{color:var(--muted)}
        code{background:var(--code);padding:3px 6px;border-radius:4px}
        details{font-size:13px;overflow-wrap:anywhere}
        a{color:inherit}
        """;

    public static String html(Role role, String inputName, String version, List<Finding> findings, Map<String, Drift> drift) {
        Summary s = summarize(findings, drift);
        StringBuilder out = new StringBuilder();
        out.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
           .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
           .append("<title>HostBaseline \u00b7 Configuration evidence</title><style>\n").append(CSS).append("</style></head>\n<body><main>\n")
           .append("<p class=\"eyebrow\">Systems / Security / Evidence</p><h1>HostBaseline</h1>")
           .append("<p>Read-only Linux configuration review from explicit snapshots.</p>\n")
           .append("<section class=\"metrics\"><div><b>").append(s.pass()).append("</b>Pass</div><div><b>").append(s.fail())
           .append("</b>Needs review</div><div><b>").append(s.unknown()).append("</b>Unknown</div><div><b>")
           .append(s.changed() == null ? "\u2014" : s.changed().toString()).append("</b>Changed checks</div></section>\n")
           .append("<p class=\"meta\">Policy: ").append(role.id()).append(" \u00b7 Input: ").append(escapeHtml(inputName))
           .append(" \u00b7 Version ").append(escapeHtml(version)).append("</p>\n")
           .append("<p>This is a narrow educational baseline, not a vulnerability scan, certification or full compliance assessment. ")
           .append("Missing, conflicting or uninterpretable evidence is UNKNOWN. Exported data may be stale or incomplete.</p>\n");
        for (Finding f : findings) {
            Rule r = f.rule();
            Drift d = drift == null ? null : drift.get(r.id());
            out.append("<article><header><b>").append(r.id()).append("</b> <span class=\"badge ").append(f.status()).append("\">")
               .append(f.status()).append("</span> <small>").append(r.severity().id()).append("</small></header>")
               .append("<h3>").append(escapeHtml(r.key())).append("</h3><p>Observed: <code>").append(escapeHtml(f.observed()))
               .append("</code> \u00b7 Expected: ").append(escapeHtml(r.matcher().describe())).append("</p>");
            if (!f.reason().isEmpty()) out.append("<p><strong>Why unknown:</strong> ").append(escapeHtml(f.reason())).append("</p>");
            out.append("<p>").append(escapeHtml(r.rationale())).append("</p><p><strong>Review:</strong> ")
               .append(escapeHtml(r.remediation())).append("</p><details><summary>Evidence &amp; drift</summary><p>")
               .append(escapeHtml(f.file())).append("; sha256=").append(escapeHtml(f.sha256())).append("</p><p>")
               .append(escapeHtml(d == null ? "No comparison" : d.describe())).append("</p><p><a href=\"")
               .append(escapeHtml(r.reference())).append("\" rel=\"noopener noreferrer\">Reference</a></p></details></article>\n");
        }
        return out.append("<footer>SSH is evaluated for the context used to export sshd -T. Network checks cover only the named keys, ")
                  .append("not every interface or IPv6. No automatic remediation.</footer>\n</main></body></html>\n").toString();
    }

    /** Console lines for everything that is not a PASS. */
    public static String consoleLines(List<Finding> findings) {
        return findings.stream().filter(f -> f.status() != Status.PASS)
                .map(f -> String.format("%-7s %s  %s: observed %s, expected %s%s", f.status(), f.rule().id(), f.rule().key(),
                        f.observed(), f.rule().matcher().describe(), f.reason().isEmpty() ? "" : " (" + f.reason() + ")"))
                .collect(Collectors.joining(System.lineSeparator()));
    }
}
