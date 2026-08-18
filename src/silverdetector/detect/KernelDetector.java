package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;

/**
 * Kernel version from {@code uname -a} / {@code uname -r} / {@code /proc/version}, matched
 * automatically against the local-privesc CVE table.
 *
 * <p>This is the "find relevant CVEs automatically" part for the kernel: parse the running
 * version, then report every row in {@code data/kernel_cves.tsv} whose range contains it -
 * Dirty COW, Dirty Pipe, the netfilter and nf_tables bugs, and so on. Ranges are mainline, so
 * each finding says "confirm against the exact build" rather than promising a win.
 */
public final class KernelDetector implements Detector {

    // Matches the release in `uname -a`, `uname -r`, or a /proc/version line.
    private static final Pattern RELEASE = Pattern.compile(
            "\\b(\\d+\\.\\d+(?:\\.\\d+)?)(-[A-Za-z0-9._+-]+)?");
    private static final Pattern UNAME_LINE = Pattern.compile("(?i)^linux\\s+\\S+\\s+\\d+\\.\\d+");
    private static final Pattern PROC_VERSION = Pattern.compile("(?i)^linux version\\s+\\d+\\.\\d+");
    private static final Pattern BARE_RELEASE = Pattern.compile("^\\d+\\.\\d+\\.\\d+\\S*$");

    @Override
    public String id() {
        return "kernel";
    }

    @Override
    public String name() {
        return "Kernel version (CVE match)";
    }

    @Override
    public String accepts() {
        return "uname -a, uname -r, or cat /proc/version";
    }

    @Override
    public int order() {
        return 60;
    }

    @Override
    public Detection sniff(Document doc) {
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            if ((UNAME_LINE.matcher(text).find() || PROC_VERSION.matcher(text).find()
                    || BARE_RELEASE.matcher(text).matches()) && RELEASE.matcher(text).find()) {
                String release = extractRelease(text);
                return Detection.of(release == null ? 40 : 90,
                        release == null ? "possible kernel version" : "kernel " + release);
            }
        }
        return Detection.NONE;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Finding> findings = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            boolean unameish = UNAME_LINE.matcher(text).find() || PROC_VERSION.matcher(text).find()
                    || BARE_RELEASE.matcher(text).matches();
            if (!unameish) {
                continue;
            }
            String release = extractRelease(text);
            if (release == null) {
                continue;
            }
            findings.addAll(assess(release, text, line.number()));
            break;   // one kernel line is enough; later lines are usually the same box
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private List<Finding> assess(String release, String evidence, int line) {
        List<Finding> findings = new ArrayList<>();
        Version version = Version.parse(release);

        List<ServiceCves.Hit> hits = new ArrayList<>();
        for (Row row : Kb.table("kernel_cves").rows()) {
            String minStr = row.get("min");
            String maxStr = row.get("max");
            Version min = minStr.isEmpty() ? null : Version.parse(minStr);
            Version max = maxStr.isEmpty() ? null : Version.parse(maxStr);
            if (version.inRange(min, max)) {
                String label = row.get("name", row.get("cve"));
                findings.add(Finding.of(Severity.parse(row.get("severity"), Severity.WARN),
                        "kernel " + release, row.get("cve") + " - " + label,
                        row.get("description"), evidence, line)
                        .note("affects mainline " + (minStr.isEmpty() ? "*" : minStr) + " - "
                                + (maxStr.isEmpty() ? "*" : maxStr))
                        .note("next: confirm the exact build (uname -v, the distro's changelog) "
                                + "before trusting a public exploit"));
                hits.add(new ServiceCves.Hit(row.get("cve"), Severity.OK, "", ""));
            }
        }

        String summary = hits.isEmpty()
                ? "No local-privesc CVE in kernel_cves.tsv matches this version. That is not a "
                  + "clean bill of health - the table only holds the headline bugs. Check a live "
                  + "source (searchsploit, the distro tracker) too."
                : hits.size() + " known local-privesc CVE" + (hits.size() == 1 ? "" : "s")
                  + " match this kernel version - see the entries above.";
        findings.add(Finding.of(hits.isEmpty() ? Severity.INFO : Severity.NOTICE,
                "kernel " + release, "running kernel " + release, summary, evidence, line)
                .note("this tool matches a curated list offline; it is a starting point, not a scan"));
        return findings;
    }

    private static String extractRelease(String text) {
        Matcher m = RELEASE.matcher(text);
        if (m.find()) {
            return m.group(1) + (m.group(2) == null ? "" : m.group(2));
        }
        return null;
    }
}
