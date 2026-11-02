package io.github.mariaax6.hostbaseline;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Check-by-check comparison of two evaluations made with the same role. */
public final class Diff {
    private Diff() {}

    public record Drift(Finding before, Finding after) {
        /** Observed-value changes count even when both values pass. */
        public boolean changed() {
            return before.status() != after.status() || !before.observed().equals(after.observed());
        }

        public String describe() {
            return changed()
                    ? before.status() + " (" + before.observed() + ") \u2192 " + after.status() + " (" + after.observed() + ")"
                    : "Unchanged";
        }
    }

    public static Map<String, Drift> compare(List<Finding> before, List<Finding> after) {
        Map<String, Finding> old = new LinkedHashMap<>();
        for (Finding f : before) old.put(f.rule().id(), f);
        Map<String, Drift> result = new LinkedHashMap<>();
        for (Finding f : after) {
            Finding previous = old.get(f.rule().id());
            if (previous != null) result.put(f.rule().id(), new Drift(previous, f));
        }
        return result;
    }

    public static long changedCount(Map<String, Drift> drift) {
        return drift.values().stream().filter(Drift::changed).count();
    }
}
