package silverdetector.core;

/**
 * Terminal colours. Everything funnels through {@link #enabled(boolean)} so that
 * {@code --no-color}, {@code NO_COLOR=1} and "stdout is a pipe" all end up in one place.
 */
public final class Ansi {

    public static final String RESET = "\u001b[0m";
    public static final String BOLD = "\u001b[1m";
    public static final String DIM = "\u001b[2m";
    public static final String RED_BOLD = "\u001b[1;31m";
    public static final String YELLOW = "\u001b[33m";
    public static final String BLUE = "\u001b[94m";
    public static final String CYAN = "\u001b[36m";
    public static final String GREEN = "\u001b[32m";
    public static final String MAGENTA = "\u001b[35m";

    private static boolean enabled = true;

    private Ansi() {
    }

    public static void enabled(boolean on) {
        enabled = on;
    }

    public static boolean enabled() {
        return enabled;
    }

    /** Wraps {@code text} in {@code code} when colour is on, otherwise returns it untouched. */
    public static String paint(String code, String text) {
        return enabled ? code + text + RESET : text;
    }

    public static String bold(String text) {
        return paint(BOLD, text);
    }

    public static String dim(String text) {
        return paint(DIM, text);
    }

    /**
     * Decides whether colour should be on when the user did not say either way.
     * The shell wrapper exports SILVERDETECTOR_COLOR because {@code [ -t 1 ]} in sh is a
     * far more reliable TTY test than anything the JDK offers across versions.
     */
    public static boolean autoDetect() {
        if (System.getenv("NO_COLOR") != null) {
            return false;
        }
        String hint = System.getenv("SILVERDETECTOR_COLOR");
        if (hint != null) {
            return hint.equals("1") || hint.equalsIgnoreCase("true") || hint.equalsIgnoreCase("always");
        }
        String term = System.getenv("TERM");
        if (term != null && term.equals("dumb")) {
            return false;
        }
        return System.console() != null;
    }
}
