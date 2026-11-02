package io.github.mariaax6.hostbaseline;

/**
 * Result of evaluating one rule.
 *
 * @param observed the value found in the snapshot, or a placeholder when none could be trusted
 * @param reason   why the status is UNKNOWN (empty for PASS and FAIL)
 * @param file     snapshot file the evidence came from
 * @param sha256   SHA-256 of that file's bytes, or "missing"
 */
public record Finding(Rule rule, Status status, String observed, String reason, String file, String sha256) {}
