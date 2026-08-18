package silverdetector.core;

/**
 * A detector's answer to "do you recognise this paste?".
 *
 * @param confidence 0-100. Anything at or above {@link #RUN_THRESHOLD} gets analysed.
 * @param summary    what the detector thinks it is looking at, shown in the report header,
 *                   e.g. "ss -tulpn socket table, 12 rows"
 */
public record Detection(int confidence, String summary) {

    /** Detectors scoring this or higher are run. */
    public static final int RUN_THRESHOLD = 50;

    /** Below RUN_THRESHOLD but at or above this, the best detector runs with a caveat. */
    public static final int GUESS_THRESHOLD = 25;

    public static final Detection NONE = new Detection(0, "");

    public Detection {
        confidence = Math.max(0, Math.min(100, confidence));
        summary = summary == null ? "" : summary;
    }

    public static Detection of(int confidence, String summary) {
        return new Detection(confidence, summary);
    }

    public static Detection of(int confidence, String format, Object... args) {
        return new Detection(confidence, String.format(format, args));
    }

    public boolean recognised() {
        return confidence >= RUN_THRESHOLD;
    }

    public boolean plausible() {
        return confidence >= GUESS_THRESHOLD;
    }
}
