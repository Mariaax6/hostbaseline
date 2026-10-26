package portfolio.hostbaseline;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public final class Main {
    static String html(String s) { return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;"); }
    static String json(String s) {
        StringBuilder out=new StringBuilder("\"");
        for(char c:s.toCharArray()) switch(c) {
            case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\");
            case '\n' -> out.append("\\n"); case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
            default -> { if(c<32) out.append(String.format("\\u%04x",(int)c)); else out.append(c); }
        }
        return out.append('"').toString();
    }
    public static void main(String[] args) {
        if(args.length==1 && args[0].equals("--help")) {
            System.out.println("HostBaseline: java -jar hostbaseline.jar <snapshot-directory> <report-directory> [workstation|router] [previous-snapshot-directory]"); return;
        }
        try {
            if(args.length<2 || args.length>4) throw new IllegalArgumentException("Use --help for usage");
            Path input=Path.of(args[0]);
            if(!Files.isDirectory(input)) throw new IOException("Snapshot directory does not exist");
            String role=args.length>2?args[2]:"workstation";
            var findings=Audit.evaluate(input,role);
            Map<String,Audit.Finding> previous=new HashMap<>();
            if(args.length>3) {
                if(!Files.isDirectory(Path.of(args[3]))) throw new IOException("Previous snapshot directory does not exist");
                for(var f:Audit.evaluate(Path.of(args[3]),role)) previous.put(f.rule().id(),f);
            }
            StringBuilder rows=new StringBuilder(), data=new StringBuilder("{\"role\":"+json(role)+",\"findings\":[");
            int pass=0,fail=0,unknown=0,changed=0;
            for(var f:findings) {
                switch(f.status()) { case PASS -> pass++; case FAIL -> fail++; case UNKNOWN -> unknown++; }
                var r=f.rule(); var old=previous.get(r.id());
                boolean drift=old!=null && (old.status()!=f.status() || !old.observed().equals(f.observed()));
                if(drift) changed++;
                String delta=old==null?"No comparison":drift?old.status()+" ("+old.observed()+") → "+f.status()+" ("+f.observed()+")":"Unchanged";
                rows.append("<article><header><b>").append(r.id()).append("</b> <span class=").append(f.status()).append(">").append(f.status()).append("</span> <small>").append(r.severity()).append("</small></header><h3>").append(html(r.key())).append("</h3><p>Observed: <code>").append(html(f.observed())).append("</code> · Expected: ").append(html(new TreeSet<>(r.expected()).toString())).append("</p><p>").append(html(r.rationale())).append("</p><p><strong>Review:</strong> ").append(html(r.remediation())).append("</p><details><summary>Evidence & drift</summary><p>").append(html(f.evidence())).append("</p><p>").append(html(delta)).append("</p></details></article>");
                if(data.charAt(data.length()-1)!='[') data.append(',');
                data.append("{\"id\":").append(json(r.id())).append(",\"key\":").append(json(r.key())).append(",\"status\":").append(json(f.status().name())).append(",\"observed\":").append(json(f.observed())).append(",\"severity\":").append(json(r.severity())).append(",\"expected\":[");
                boolean comma=false; for(String value:new TreeSet<>(r.expected())) { if(comma) data.append(','); data.append(json(value)); comma=true; }
                data.append("],\"evidence\":").append(json(f.evidence())).append(",\"remediation\":").append(json(r.remediation())).append(",\"drift\":").append(old==null?"null":json(delta)).append('}');
            }
            data.append("],\"pass\":").append(pass).append(",\"fail\":").append(fail).append(",\"unknown\":").append(unknown).append(",\"changed\":").append(changed).append("}\n");
            String page="""
                <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HostBaseline · Configuration evidence</title><style>
                body{font:16px system-ui;background:#f0f3f8;color:#16283e;max-width:1100px;margin:45px auto;padding:0 24px}h1{font-size:46px;margin-bottom:0}p{line-height:1.6}.metrics{display:flex;gap:32px;flex-wrap:wrap;background:#142c45;color:white;padding:26px;border-radius:14px;margin:28px 0}.metrics b{display:block;font-size:32px}article{background:white;border:1px solid #d6e0ea;border-radius:12px;margin:18px 0;padding:24px}header{display:flex;gap:16px;align-items:center}.PASS{color:#147148}.FAIL{color:#ac2836}.UNKNOWN{color:#876010}small{color:#6b8096}code{background:#edf2f7;padding:3px 6px}details{font-size:13px;overflow-wrap:anywhere}footer{margin:30px 0;color:#53657b}
                </style><small>SYSTEMS / SECURITY / EVIDENCE</small><h1>HostBaseline</h1><p>Read-only Linux configuration review from explicit snapshots.</p>
                """+
                "<section class=metrics><div><b>"+pass+"</b>Pass</div><div><b>"+fail+"</b>Needs review</div><div><b>"+unknown+"</b>Unknown</div><div><b>"+changed+"</b>Changed checks</div></section><p>Policy: "+role+" · Input: "+html(input.getFileName().toString())+"</p><p>This is a narrow educational baseline, not a vulnerability scan, certification or full compliance assessment. Missing/conflicting evidence is UNKNOWN. Exported data may be stale or incomplete.</p>"+rows+"<footer>SSH is evaluated for the context used to export sshd -T. Network checks cover only the named keys, not every interface or IPv6. No automatic remediation.</footer></html>";
            Path out=Path.of(args[1]); Files.createDirectories(out);
            Files.writeString(out.resolve("report.html"),page); Files.writeString(out.resolve("findings.json"),data);
            System.out.printf("PASS=%d FAIL=%d UNKNOWN=%d CHANGED=%d%nReport: %s%n",pass,fail,unknown,changed,out.toAbsolutePath().resolve("report.html"));
            // 0 = complete and passing; 1 = failed checks; 3 = unknown evidence; 2 = input/usage error.
            System.exit(fail>0?1:unknown>0?3:0);
        } catch(IOException|IllegalArgumentException e) { System.err.println("HostBaseline: "+e.getMessage()); System.exit(2); }
    }
}
