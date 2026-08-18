package silverdetector.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import silverdetector.detect.CapabilitiesDetector;
import silverdetector.detect.PortsDetector;
import silverdetector.detect.SetuidDetector;
import silverdetector.detect.WindowsFoldersDetector;

/**
 * The list of everything SilverDetector knows how to read.
 *
 * <p>ADD YOUR DETECTOR HERE - one {@code detectors.add(...)} line below and it is live:
 * auto-detection, {@code --detector <id>}, {@code --list} and JSON output all pick it up.
 * See {@code docs/ADDING_DETECTORS.md}.
 */
public final class DetectorRegistry {

    private DetectorRegistry() {
    }

    public static List<Detector> all() {
        List<Detector> detectors = new ArrayList<>();

        detectors.add(new SetuidDetector());        // find / -perm -4000 (and -2000)
        detectors.add(new PortsDetector());         // ss / netstat / nmap / lsof
        detectors.add(new CapabilitiesDetector());  // getcap -r /

        // Worked example from docs/ADDING_DETECTORS.md. Uncomment to switch it on.
        // detectors.add(new WindowsFoldersDetector());

        // ---- your detectors go here -------------------------------------------------

        detectors.sort(Comparator.comparingInt(Detector::order).thenComparing(Detector::id));
        return detectors;
    }

    /** Looks a detector up by id, case-insensitively. Returns null when there is no such id. */
    public static Detector byId(String id) {
        for (Detector detector : all()) {
            if (detector.id().equalsIgnoreCase(id)) {
                return detector;
            }
        }
        return null;
    }

    public static List<String> ids() {
        List<String> ids = new ArrayList<>();
        for (Detector detector : all()) {
            ids.add(detector.id());
        }
        return ids;
    }
}
