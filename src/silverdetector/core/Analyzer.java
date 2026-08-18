package silverdetector.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Runs the detectors: asks each one whether it recognises the paste, then analyses with
 * whichever ones said yes. A paste holding both a port table and a SUID list gets both.
 */
public final class Analyzer {

    /** One detector's verdict plus what it found. */
    public record Run(Detector detector, Detection detection, List<Finding> findings, boolean guessed) {

        public Severity worst() {
            Severity worst = Severity.OK;
            for (Finding finding : findings) {
                worst = worst.max(finding.severity());
            }
            return worst;
        }

        public long anomalyCount() {
            return findings.stream().filter(Finding::isAnomaly).count();
        }
    }

    /** Everything the report needs. {@code sniffs} is kept so we can explain a non-detection. */
    public record Result(Document document, List<Run> runs, List<Run> sniffs) {

        public boolean recognised() {
            return !runs.isEmpty();
        }

        public Severity worst() {
            Severity worst = Severity.OK;
            for (Run run : runs) {
                worst = worst.max(run.worst());
            }
            return worst;
        }

        public List<Finding> allFindings() {
            List<Finding> all = new ArrayList<>();
            runs.forEach(run -> all.addAll(run.findings()));
            return all;
        }
    }

    private Analyzer() {
    }

    /** Auto-detecting run across every registered detector. */
    public static Result run(Document doc) {
        return run(doc, DetectorRegistry.all(), null);
    }

    /**
     * @param forced when non-null, that detector runs regardless of what sniffing says
     */
    public static Result run(Document doc, List<Detector> detectors, Detector forced) {
        List<Run> sniffs = new ArrayList<>();
        for (Detector detector : detectors) {
            Detection detection;
            try {
                detection = detector.sniff(doc);
            } catch (RuntimeException e) {
                detection = Detection.NONE;
            }
            sniffs.add(new Run(detector, detection == null ? Detection.NONE : detection, List.of(), false));
        }
        sniffs.sort(Comparator.comparingInt((Run r) -> r.detection().confidence()).reversed()
                .thenComparingInt(r -> r.detector().order()));

        List<Run> chosen = new ArrayList<>();
        if (forced != null) {
            Detection detection = sniffs.stream()
                    .filter(r -> r.detector().id().equals(forced.id()))
                    .map(Run::detection)
                    .findFirst()
                    .orElse(Detection.NONE);
            chosen.add(new Run(forced, detection, analyse(forced, doc), false));
            return new Result(doc, chosen, sniffs);
        }

        for (Run sniff : sniffs) {
            if (sniff.detection().recognised()) {
                chosen.add(new Run(sniff.detector(), sniff.detection(), analyse(sniff.detector(), doc), false));
            }
        }

        // Nothing was confident. Take the best plausible guess rather than giving up.
        if (chosen.isEmpty() && !sniffs.isEmpty() && sniffs.get(0).detection().plausible()) {
            Run best = sniffs.get(0);
            chosen.add(new Run(best.detector(), best.detection(), analyse(best.detector(), doc), true));
        }

        // Keep detectors that actually produced something; a 50%-confident detector that
        // found nothing to say is just noise in the report.
        List<Run> useful = new ArrayList<>();
        for (Run run : chosen) {
            if (!run.findings().isEmpty()) {
                useful.add(run);
            }
        }
        return new Result(doc, useful, sniffs);
    }

    private static List<Finding> analyse(Detector detector, Document doc) {
        try {
            List<Finding> findings = detector.analyze(doc);
            return findings == null ? List.of() : findings;
        } catch (RuntimeException e) {
            return List.of(Finding.of(Severity.WARN, detector.id(), "detector failed",
                    detector.getClass().getSimpleName() + " threw " + e, "", 0));
        }
    }
}
