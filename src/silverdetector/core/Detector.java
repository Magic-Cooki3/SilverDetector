package silverdetector.core;

import java.util.List;

/**
 * A thing that recognises one kind of command output and says what is normal in it.
 *
 * <p>To add your own: implement this interface in {@code silverdetector.detect}, add one line
 * to {@link DetectorRegistry}, rebuild. See {@code docs/ADDING_DETECTORS.md} for a worked
 * example (Windows default folders).
 *
 * <p>Two rules keep the output useful:
 * <ul>
 *   <li>{@link #sniff} must be cheap and must not throw. It only decides "is this mine?".</li>
 *   <li>{@link #analyze} emits a {@link Finding} for <em>every</em> row it understands, including
 *       the boring ones at {@link Severity#OK} - the point is to name and explain the normal
 *       stuff, not only to shout about the odd stuff.</li>
 * </ul>
 */
public interface Detector {

    /** Short stable handle, used by {@code --detector} and in JSON output. e.g. "ports". */
    String id();

    /** Human name for the report header. e.g. "Listening ports / sockets". */
    String name();

    /** What input it eats, shown by {@code --list}. e.g. "ss -tulpn, netstat -tulpn, nmap". */
    String accepts();

    /** How sure it is that this paste belongs to it. Must never throw. */
    Detection sniff(Document doc);

    /** The actual analysis. Only called when {@link #sniff} scored high enough. */
    List<Finding> analyze(Document doc);

    /** Tie-break order when two detectors score the same; lower runs first. */
    default int order() {
        return 100;
    }
}
