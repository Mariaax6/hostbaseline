package io.github.mariaax6.hostbaseline;

import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/** One baseline check: where to look, what is acceptable and how to explain it. */
public record Rule(String id, Source source, String key, Matcher matcher, Severity severity,
                   String rationale, String remediation, String reference) {

    /** Snapshot file a rule reads from. */
    public enum Source {
        SSH("sshd-effective.txt"), SYSCTL("sysctl-effective.txt");

        private final String fileName;
        Source(String fileName) { this.fileName = fileName; }
        public String fileName() { return fileName; }
        public String id() { return name().toLowerCase(Locale.ROOT); }
    }

    public enum Severity {
        HIGH, MEDIUM, LOW;
        public String id() { return name().toLowerCase(Locale.ROOT); }
    }

    /** Decides whether an observed (already lower-cased, non-empty) value satisfies a rule. */
    public sealed interface Matcher permits OneOf, Range {
        /** PASS, FAIL, or UNKNOWN when the value cannot be interpreted. */
        Status test(String observed);
        String describe();
    }

    /** The observed value must be exactly one of the accepted values. */
    public record OneOf(Set<String> values) implements Matcher {
        public OneOf { values = Set.copyOf(values); }
        @Override public Status test(String observed) { return values.contains(observed) ? Status.PASS : Status.FAIL; }
        @Override public String describe() { return String.join(" or ", new TreeSet<>(values)); }
    }

    /** The observed value must be an integer within [min, max]; anything else is UNKNOWN. */
    public record Range(long min, long max) implements Matcher {
        @Override public Status test(String observed) {
            try {
                long value = Long.parseLong(observed);
                return value >= min && value <= max ? Status.PASS : Status.FAIL;
            } catch (NumberFormatException e) {
                return Status.UNKNOWN;
            }
        }
        @Override public String describe() { return "between " + min + " and " + max; }
    }

    public static OneOf oneOf(String... values) { return new OneOf(Set.of(values)); }
}
