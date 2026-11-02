package io.github.mariaax6.hostbaseline;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * A parsed, bounded and fingerprinted snapshot file. Only explicit "effective" exports are
 * accepted: raw sshd_config (Include/Match) is rejected because it cannot be evaluated offline.
 */
public record Snapshot(Map<String, String> values, Set<String> ambiguous, String sha256, boolean present) {

    static final int MAX_BYTES = 4 * 1024 * 1024;

    public static Snapshot absent() { return new Snapshot(Map.of(), Set.of(), "missing", false); }

    public static Snapshot load(Path file, Rule.Source source) throws IOException {
        if (!Files.exists(file)) return absent();
        String name = file.getFileName().toString();
        if (!Files.isRegularFile(file)) throw new IOException("Not a regular file: " + name);
        if (Files.size(file) > MAX_BYTES) throw new IOException("Snapshot exceeds 4 MiB: " + name);
        byte[] bytes;
        try (InputStream in = Files.newInputStream(file)) { bytes = in.readNBytes(MAX_BYTES + 1); }
        if (bytes.length > MAX_BYTES) throw new IOException("Snapshot grew beyond 4 MiB while reading: " + name);
        return parse(bytes, source, name);
    }

    static Snapshot parse(byte[] bytes, Rule.Source source, String name) throws IOException {
        String text = decode(bytes, name);
        boolean ssh = source == Rule.Source.SSH;
        Map<String, String> values = new HashMap<>();
        Set<String> ambiguous = new HashSet<>();
        int lineNo = 0;
        for (String raw : text.split("\\R")) {
            lineNo++;
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String lower = line.toLowerCase(Locale.ROOT);
            if (ssh && (lower.startsWith("include ") || lower.startsWith("match "))) {
                throw new IOException("Raw SSH configuration is not supported. Supply sshd -T output (line " + lineNo + ")");
            }
            String[] parts = ssh ? line.split("\\s+", 2) : line.split("\\s*=\\s*", 2);
            if (parts.length != 2 || parts[0].isEmpty()) {
                throw new IOException("Invalid snapshot syntax at " + name + ":" + lineNo);
            }
            String key = ssh ? parts[0].toLowerCase(Locale.ROOT) : parts[0];
            String value = parts[1].strip().toLowerCase(Locale.ROOT);
            String previous = values.putIfAbsent(key, value);
            if (previous != null && !previous.equals(value)) ambiguous.add(key);
        }
        return new Snapshot(Map.copyOf(values), Set.copyOf(ambiguous), sha256Hex(bytes), true);
    }

    /** Strict UTF-8: malformed input is an error, never silently repaired. */
    private static String decode(byte[] bytes, String name) throws IOException {
        boolean utf16 = bytes.length >= 2
                && ((bytes[0] == (byte) 0xFF && bytes[1] == (byte) 0xFE) || (bytes[0] == (byte) 0xFE && bytes[1] == (byte) 0xFF));
        if (utf16) {
            throw new IOException(name + " looks like UTF-16 (for example PowerShell '>' redirection). Re-export it as UTF-8");
        }
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            return text.startsWith("\uFEFF") ? text.substring(1) : text;
        } catch (CharacterCodingException e) {
            throw new IOException(name + " is not valid UTF-8");
        }
    }

    static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
