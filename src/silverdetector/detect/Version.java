package silverdetector.detect;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A dotted version number pulled out of messier text - "Apache/2.4.49 (Unix)",
 * "vsFTPd 2.3.4", "5.4.0-42-generic". Only the leading numeric run is kept
 * ({@code 2.4.49}); suffixes like {@code p1} or {@code -generic} are ignored for comparison,
 * which is accurate enough to place a version inside a known-vulnerable range.
 *
 * <p>This is the machinery behind "find relevant CVEs automatically": a detector parses the
 * version it saw, and the CVE tables give {@code min}/{@code max} bounds to test it against.
 */
final class Version implements Comparable<Version> {

    private static final Pattern NUMERIC = Pattern.compile("(\\d+(?:\\.\\d+)*)");

    private final int[] parts;
    private final String raw;

    private Version(int[] parts, String raw) {
        this.parts = parts;
        this.raw = raw;
    }

    /** Extracts the first dotted-number run from {@code text}; invalid when there is none. */
    static Version parse(String text) {
        if (text == null) {
            return new Version(new int[0], "");
        }
        Matcher m = NUMERIC.matcher(text);
        if (!m.find()) {
            return new Version(new int[0], text.strip());
        }
        String[] bits = m.group(1).split("\\.");
        int[] parsed = new int[bits.length];
        for (int i = 0; i < bits.length; i++) {
            try {
                parsed[i] = Integer.parseInt(bits[i]);
            } catch (NumberFormatException e) {
                parsed[i] = 0;
            }
        }
        return new Version(parsed, m.group(1));
    }

    boolean valid() {
        return parts.length > 0;
    }

    @Override
    public int compareTo(Version other) {
        int n = Math.max(parts.length, other.parts.length);
        for (int i = 0; i < n; i++) {
            int a = i < parts.length ? parts[i] : 0;
            int b = i < other.parts.length ? other.parts[i] : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        return 0;
    }

    /**
     * True when this version falls in [{@code min}, {@code max}] inclusive. A null or invalid
     * bound is treated as open, so a row can say "everything up to X" or "X and later".
     */
    boolean inRange(Version min, Version max) {
        if (!valid()) {
            return false;
        }
        if (min != null && min.valid() && compareTo(min) < 0) {
            return false;
        }
        if (max != null && max.valid() && compareTo(max) > 0) {
            return false;
        }
        return true;
    }

    String raw() {
        return raw;
    }

    @Override
    public String toString() {
        return raw;
    }
}
