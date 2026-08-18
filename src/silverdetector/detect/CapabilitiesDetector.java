package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;
import silverdetector.core.Table;

/**
 * File capabilities: {@code getcap -r / 2>/dev/null}.
 *
 * <p>The modern replacement for a lot of SUID bits, and the place people forget to look -
 * {@code cap_setuid} on an interpreter is every bit as good as SUID root.
 *
 * <p>This is also the shortest detector in the tree, so it doubles as a worked example of how
 * much code a new one actually needs: parse, look up, emit findings.
 */
public final class CapabilitiesDetector implements Detector {

    // /usr/bin/ping cap_net_raw=ep     |     /usr/bin/ping = cap_net_raw+ep
    private static final Pattern LINE = Pattern.compile(
            "^(\\S+)\\s+(?:=\\s+)?((?:cap_[a-z_]+)(?:\\s*,\\s*cap_[a-z_]+)*)\\s*([=+][eipEIP]*)\\s*$");

    @Override
    public String id() {
        return "caps";
    }

    @Override
    public String name() {
        return "File capabilities";
    }

    @Override
    public String accepts() {
        return "getcap -r / output";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Document.Line> lines = doc.contentLines();
        if (lines.isEmpty()) {
            return Detection.NONE;
        }
        int matched = 0;
        for (Document.Line line : lines) {
            if (LINE.matcher(line.text().strip()).matches()) {
                matched++;
            }
        }
        if (matched == 0) {
            return Detection.NONE;
        }
        int confidence = Math.min(97, 60 + (100 * matched / lines.size()) * 37 / 100);
        return Detection.of(confidence, "getcap listing, %d file%s", matched, matched == 1 ? "" : "s");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table caps = Kb.table("capabilities");
        Table knownFiles = Kb.table("caps_known");

        List<Finding> findings = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            Matcher m = LINE.matcher(line.text().strip());
            if (!m.matches()) {
                continue;
            }
            String path = m.group(1);
            String flags = m.group(3);
            Set<String> granted = new LinkedHashSet<>();
            for (String cap : m.group(2).split("\\s*,\\s*")) {
                granted.add(cap.strip().toLowerCase());
            }
            findings.add(assess(line, path, granted, flags, caps, knownFiles));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assess(Document.Line line, String path, Set<String> granted, String flags,
                           Table caps, Table knownFiles) {
        Severity severity = Severity.OK;
        List<String> explanations = new ArrayList<>();
        for (String cap : granted) {
            Row row = caps.first(cap);
            if (row == null) {
                severity = severity.max(Severity.NOTICE);
                explanations.add(cap + ": not in capabilities.tsv - look it up in capabilities(7)");
                continue;
            }
            severity = severity.max(Severity.parse(row.get("severity"), Severity.NOTICE));
            explanations.add(cap + ": " + row.get("description"));
        }

        // "+ep" or "=ep" means effective+permitted: it applies without the program asking.
        boolean effective = flags.toLowerCase().contains("e");
        if (!effective && severity.atLeast(Severity.WARN)) {
            severity = Severity.NOTICE;
        }

        Row known = knownFiles.first(path);
        String label;
        String detail;
        if (known != null && capsMatch(known.get("caps"), granted)) {
            // Exactly what the distro ships: the knowledge base row has the final say, so
            // /usr/bin/ping with cap_net_raw comes out OK instead of "raw sockets, scary".
            label = known.get("purpose", basename(path));
            detail = known.get("description", "shipped with these capabilities by the distro.");
            severity = Severity.parse(known.get("severity"), Severity.OK);
        } else {
            label = basename(path) + (known == null ? "" : " (capabilities differ from the packaged set)");
            detail = known == null
                    ? "Not in caps_known.tsv. Capabilities on a binary that the distro does not ship "
                      + "with them is a classic persistence trick - check the owning package."
                    : "Packaged with " + known.get("caps") + ", but this file has "
                      + String.join(",", granted) + ".";
            severity = severity.max(Severity.NOTICE);
        }

        Finding finding = Finding.of(severity, path, label, detail, line.text().strip(), line.number())
                .note("capabilities: " + String.join(", ", granted) + flags);
        for (String explanation : explanations) {
            finding = finding.note(explanation);
        }
        if (!effective) {
            finding = finding.note("no 'e' flag: the binary has to raise the capability itself, "
                                   + "which limits (but does not remove) the risk");
        }
        return finding;
    }

    private static boolean capsMatch(String expected, Set<String> granted) {
        if (expected == null || expected.isBlank()) {
            return false;
        }
        Set<String> want = new LinkedHashSet<>();
        for (String cap : expected.split("\\s*,\\s*")) {
            want.add(cap.strip().toLowerCase());
        }
        return want.equals(granted);
    }

    private static String basename(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }
}
