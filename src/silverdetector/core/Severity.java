package silverdetector.core;

/**
 * How worried you should be about a single finding.
 *
 * <p>Detectors only ever pick one of these; the report and the process exit code
 * are derived from them, so adding a new level here changes both at once.
 */
public enum Severity {

    /** Expected, documented, boring. Listed so you can see what the thing is. */
    OK(0, "OK", Ansi.GREEN),

    /** Not an anomaly, just context worth printing (ephemeral socket, symlink, ...). */
    INFO(1, "INFO", Ansi.CYAN),

    /** Unrecognised or slightly off. Look at it, but it is probably fine. */
    NOTICE(2, "NOTICE", Ansi.BLUE),

    /** Off the beaten path: legacy service, unexpected SUID binary, cleartext protocol. */
    WARN(3, "WARN", Ansi.YELLOW),

    /** Straight-up privilege escalation vector or a listener that should not exist. */
    CRITICAL(4, "CRIT", Ansi.RED_BOLD);

    private final int rank;
    private final String label;
    private final String colour;

    Severity(int rank, String label, String colour) {
        this.rank = rank;
        this.label = label;
        this.colour = colour;
    }

    public int rank() {
        return rank;
    }

    public String label() {
        return label;
    }

    public String colour() {
        return colour;
    }

    /** True for anything that is not "this is the normal state of the world". */
    public boolean isAnomaly() {
        return rank >= NOTICE.rank;
    }

    public boolean atLeast(Severity other) {
        return rank >= other.rank;
    }

    /** Returns the more severe of the two. */
    public Severity max(Severity other) {
        return rank >= other.rank ? this : other;
    }

    /** One step up the ladder, saturating at {@link #CRITICAL}. */
    public Severity escalate() {
        Severity[] all = values();
        return this == CRITICAL ? CRITICAL : all[ordinal() + 1];
    }

    public static Severity parse(String s, Severity fallback) {
        if (s == null) {
            return fallback;
        }
        for (Severity sev : values()) {
            if (sev.name().equalsIgnoreCase(s.trim())) {
                return sev;
            }
        }
        return fallback;
    }
}
