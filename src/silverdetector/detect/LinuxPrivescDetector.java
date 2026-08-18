package silverdetector.detect;

import java.util.Comparator;
import java.util.List;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Severity;

/**
 * Linux local privilege escalation - the linPEAS counterpart to {@link WindowsPrivescDetector},
 * and the same "paste a scan you don't understand and be told what it is" idea.
 *
 * <p>The structured Linux detectors ({@code sudo}, {@code setuid}, {@code caps}, {@code cron},
 * {@code kernel}, {@code passwd}, {@code shadow}) already read the parts of a linPEAS run they
 * are good at. This detector covers the rest of the HackTricks Linux checklist through the shared
 * {@link Signatures} engine and {@code data/linux_signatures.tsv}: writable {@code /etc/passwd} or
 * {@code sudoers}, {@code no_root_squash}, the docker socket, {@code ld.so.preload}, SSH keys,
 * credentials in files, and the CVE tags linPEAS itself prints (PwnKit, Dirty Pipe, ...).
 *
 * <p>So a linPEAS paste lights up both: the structured detectors for sudo/SUID/kernel/caps, and
 * this one for everything else - each finding saying what it is and where to take it.
 */
public final class LinuxPrivescDetector implements Detector {

    @Override
    public String id() {
        return "linprivesc";
    }

    @Override
    public String name() {
        return "Linux privilege escalation (linPEAS / checklist)";
    }

    @Override
    public String accepts() {
        return "linPEAS output, or Linux enum output (writable files, NFS, docker, keys, CVE tags)";
    }

    @Override
    public int order() {
        return 9;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Signatures.Sig> signatures = Signatures.load("linux_signatures");
        int sigHits = 0;
        boolean linpeas = false;

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            String lower = text.toLowerCase();
            if (lower.contains("linpeas") || lower.contains("linux privilege escalation")
                    || lower.contains("linux local privilege")) {
                linpeas = true;
            }
            if (Signatures.anyMatch(signatures, text)) {
                sigHits++;
            }
        }

        if (!linpeas && sigHits == 0) {
            return Detection.NONE;
        }
        int confidence = (linpeas ? 70 : 25) + Math.min(45, sigHits * 12) + (sigHits > 0 ? 10 : 0);
        String summary = linpeas ? "linPEAS / Linux privesc scan" : "Linux enumeration output";
        return Detection.of(Math.min(98, confidence),
                summary + ", " + sigHits + " signal" + (sigHits == 1 ? "" : "s"));
    }

    @Override
    public List<Finding> analyze(Document doc) {
        boolean linpeas = false;
        for (Document.Line line : doc.contentLines()) {
            String lower = Signatures.clean(line.text()).toLowerCase();
            if (lower.contains("linpeas") || lower.contains("linux privilege escalation")) {
                linpeas = true;
                break;
            }
        }

        List<Finding> findings = Signatures.scan(Signatures.load("linux_signatures"), doc);

        if (linpeas && findings.isEmpty()) {
            findings.add(Finding.of(Severity.INFO, "linpeas", "linPEAS run recognised",
                    "No extra signature fired here, but a linPEAS run also feeds the structured "
                    + "Linux detectors - check the sudo, SUID, capabilities, cron and kernel "
                    + "findings in this report, which cover the bulk of the checklist.", "", 0));
        } else if (linpeas) {
            findings.add(Finding.of(Severity.INFO, "linpeas", "linPEAS run recognised",
                    "These signatures cover the checklist items the structured detectors don't - "
                    + "sudo, SUID, capabilities, cron and kernel are reported separately above/below.",
                    "", 0));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }
}
