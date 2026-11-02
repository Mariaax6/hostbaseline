package io.github.mariaax6.hostbaseline;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.github.mariaax6.hostbaseline.Diff.Drift;

/** Command-line entry point. All logic lives in {@link #run} so tests can call it without System.exit. */
public final class Main {
    private Main() {}

    public static final String VERSION = "2.0.0";

    static final String USAGE = """
        HostBaseline %s - read-only Linux configuration auditor

        Usage:
          java -jar hostbaseline.jar <snapshot-dir> <report-dir> [options]

        Options:
          --role workstation|router   Baseline role (default: workstation)
          --baseline <dir>            Previous snapshot directory to compare against
          --list-checks               Print the checks for the selected role and exit
          --version                   Print the version and exit
          -h, --help                  Show this help

        Snapshot directories contain sshd-effective.txt (sshd -T) and sysctl-effective.txt (sysctl -a).
        Exit codes: 0 all pass; 1 failed checks; 3 unknown evidence without failures; 2 invalid input or usage.
        """.formatted(VERSION);

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        try {
            List<String> positional = new ArrayList<>();
            Role role = Role.WORKSTATION;
            String baseline = null;
            boolean listChecks = false;
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> { out.print(USAGE); return 0; }
                    case "--version" -> { out.println("HostBaseline " + VERSION); return 0; }
                    case "--list-checks" -> listChecks = true;
                    case "--role" -> role = Role.parse(optionValue(args, ++i, arg));
                    case "--baseline" -> baseline = optionValue(args, ++i, arg);
                    default -> {
                        if (arg.startsWith("-")) throw new IllegalArgumentException("Unknown option: " + arg + ". Use --help for usage");
                        positional.add(arg);
                    }
                }
            }
            if (listChecks) { printChecks(role, out); return 0; }
            if (positional.size() != 2) throw new IllegalArgumentException("Expected <snapshot-dir> and <report-dir>. Use --help for usage");

            Path input = Path.of(positional.get(0));
            if (!Files.isDirectory(input)) throw new IOException("Snapshot directory does not exist: " + input);
            List<Finding> findings = Audit.evaluate(input, role);

            Map<String, Drift> drift = null;
            if (baseline != null) {
                Path previous = Path.of(baseline);
                if (!Files.isDirectory(previous)) throw new IOException("Baseline snapshot directory does not exist: " + previous);
                drift = Diff.compare(Audit.evaluate(previous, role), findings);
            }

            Path reportDir = Path.of(positional.get(1));
            Files.createDirectories(reportDir);
            String inputName = input.toAbsolutePath().normalize().getFileName() == null ? input.toString()
                    : input.toAbsolutePath().normalize().getFileName().toString();
            Files.writeString(reportDir.resolve("report.html"), Report.html(role, inputName, VERSION, findings, drift));
            Files.writeString(reportDir.resolve("findings.json"), Report.json(role, VERSION, findings, drift));

            Report.Summary s = Report.summarize(findings, drift);
            out.printf("HostBaseline %s | role=%s | input=%s%n", VERSION, role.id(), inputName);
            out.printf("PASS=%d FAIL=%d UNKNOWN=%d%s%n", s.pass(), s.fail(), s.unknown(), s.changed() == null ? "" : " CHANGED=" + s.changed());
            String lines = Report.consoleLines(findings);
            if (!lines.isEmpty()) out.println(lines);
            out.println("Report: " + reportDir.toAbsolutePath().resolve("report.html"));
            // 0 = complete and passing; 1 = failed checks; 3 = unknown evidence only; 2 = input/usage error.
            return s.fail() > 0 ? 1 : s.unknown() > 0 ? 3 : 0;
        } catch (IOException | IllegalArgumentException e) {
            err.println("HostBaseline: " + e.getMessage());
            return 2;
        }
    }

    private static String optionValue(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException("Option " + option + " needs a value");
        return args[index];
    }

    private static void printChecks(Role role, PrintStream out) {
        out.println("| ID | Severity | Source | Key | Expected (" + role.id() + ") |");
        out.println("|---|---|---|---|---|");
        for (Rule r : Audit.rules(role)) {
            out.println("| " + r.id() + " | " + r.severity().id() + " | " + r.source().id() + " | `" + r.key() + "` | " + r.matcher().describe() + " |");
        }
    }
}
