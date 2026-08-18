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
 * Group membership from {@code id} (or {@code groups}). The first thing many people run after
 * landing on a box, because a single group can be the whole privilege-escalation path -
 * {@code docker}, {@code lxd}, {@code disk} and {@code shadow} are each root in disguise.
 *
 * <p>Knowledge: {@code data/groups.tsv} (group -> severity, what it grants, the next step).
 */
public final class GroupsDetector implements Detector {

    // uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),999(docker)
    private static final Pattern ID_LINE = Pattern.compile(
            "\\bgroups=([0-9]+\\([^)]*\\)(?:,[0-9]+\\([^)]*\\))*)");
    private static final Pattern ID_HEADER = Pattern.compile(
            "\\buid=([0-9]+)\\(([^)]*)\\)\\s+gid=([0-9]+)\\(([^)]*)\\)");
    private static final Pattern GROUP_TOKEN = Pattern.compile("[0-9]+\\(([^)]+)\\)");

    @Override
    public String id() {
        return "groups";
    }

    @Override
    public String name() {
        return "Group membership (id)";
    }

    @Override
    public String accepts() {
        return "id (uid=..(..) gid=..(..) groups=..) output";
    }

    @Override
    public int order() {
        return 12;
    }

    @Override
    public Detection sniff(Document doc) {
        for (Document.Line line : doc.contentLines()) {
            if (ID_HEADER.matcher(line.text()).find() && ID_LINE.matcher(line.text()).find()) {
                return Detection.of(95, "id output");
            }
        }
        // A bare "groups=..(..)" without the uid header is still recognisable, just less certain.
        for (Document.Line line : doc.contentLines()) {
            if (ID_LINE.matcher(line.text()).find()) {
                return Detection.of(60, "group membership");
            }
        }
        return Detection.NONE;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table table = Kb.table("groups");
        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        for (Document.Line line : doc.contentLines()) {
            Matcher header = ID_HEADER.matcher(line.text());
            String primaryUser = null;
            long uid = -1;
            if (header.find()) {
                uid = parse(header.group(1));
                primaryUser = header.group(2);
                if (uid == 0) {
                    findings.add(Finding.of(Severity.CRITICAL, "uid=0", "you are already root",
                            "This id shows UID 0 - you are root on this host. Enumeration is for "
                            + "persistence and lateral movement now, not escalation.",
                            line.text().strip(), line.number()));
                }
            }

            Matcher groupsMatcher = ID_LINE.matcher(line.text());
            if (!groupsMatcher.find()) {
                continue;
            }
            Matcher token = GROUP_TOKEN.matcher(groupsMatcher.group(1));
            while (token.find()) {
                String group = token.group(1);
                if (!seen.add(group.toLowerCase())) {
                    continue;
                }
                findings.add(assess(group, group.equalsIgnoreCase(primaryUser), table,
                        line.text().strip(), line.number()));
            }
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assess(String group, boolean isPrimary, Table table, String evidence, int line) {
        Row row = table.first(group);
        Severity severity = row != null ? Severity.parse(row.get("severity"), Severity.OK) : Severity.OK;
        String detail = row != null && row.has("description")
                ? row.get("description")
                : "No special privilege recorded for this group. Its own group name is usually just "
                  + "the user's private group or a benign device group.";
        String label = describe(group, isPrimary, severity);

        Finding finding = Finding.of(severity, group, label, detail, evidence, line);
        if (row != null && row.has("exploit") && !row.get("exploit").equals("-")) {
            finding = finding.note("next: " + row.get("exploit"));
        }
        if (isPrimary) {
            finding = finding.note("this is the account's own primary group");
        }
        return finding;
    }

    private static String describe(String group, boolean isPrimary, Severity severity) {
        if (severity.atLeast(Severity.WARN)) {
            return "high-value group";
        }
        if (severity == Severity.NOTICE) {
            return "useful group";
        }
        return isPrimary ? "primary group" : "group";
    }

    private static long parse(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
