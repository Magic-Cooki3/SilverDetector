package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
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
 * Windows local privilege escalation - the "throw a winPEAS dump in and be told what matters"
 * detector, built straight off the HackTricks Windows privesc checklist.
 *
 * <p>It works on a full winPEAS run or on a raw snippet ({@code whoami /priv}, {@code whoami
 * /groups}, {@code sc qc}, {@code reg query}, ...), and reports three kinds of thing:
 * <ul>
 *   <li><b>token privileges</b> - SeImpersonate and friends, from {@code data/windows_privileges.tsv}</li>
 *   <li><b>privileged groups</b> - Administrators, Backup Operators, DnsAdmins, from {@code windows_groups.tsv}</li>
 *   <li><b>signatures</b> - AlwaysInstallElevated, unquoted paths, WDigest, GPP passwords and
 *       ~40 more, from {@code data/windows_signatures.tsv}, matched by the shared
 *       {@link Signatures} engine</li>
 * </ul>
 * Every finding says what it is and where to look / how to abuse it, so a pentester who does not
 * recognise a line in a scan can paste it here and get pointed at the technique.
 *
 * <p>All the knowledge is in the three .tsv files, so covering one more checklist item is a new
 * row, not new code.
 */
public final class WindowsPrivescDetector implements Detector {

    private static final Pattern PRIVILEGE = Pattern.compile("\\bSe[A-Z][A-Za-z]+Privilege\\b");
    // DOMAIN\Group Name, where the name runs up to the next column (2+ spaces / tab / comma).
    private static final Pattern GROUP_LINE = Pattern.compile(
            "(?i)(BUILTIN|NT AUTHORITY|NT SERVICE|[A-Za-z0-9.-]+)\\\\([A-Za-z0-9][A-Za-z0-9 _-]*?)"
                    + "(?:\\s{2,}|\\t|,|$)");

    @Override
    public String id() {
        return "winprivesc";
    }

    @Override
    public String name() {
        return "Windows privilege escalation (winPEAS / checklist)";
    }

    @Override
    public String accepts() {
        return "winPEAS output, whoami /priv, whoami /groups, sc qc, reg query, or any Windows enum dump";
    }

    @Override
    public int order() {
        return 8;
    }

    @Override
    public Detection sniff(Document doc) {
        if (looksLikeLinpeas(doc)) {
            return Detection.NONE;   // a Linux scan - let the Linux detectors handle it
        }
        List<Signatures.Sig> signatures = Signatures.load("windows_signatures");
        int sigHits = 0;
        int privHits = 0;
        boolean winpeas = false;
        boolean windowsish = false;

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            String lower = text.toLowerCase();
            if (lower.contains("winpeas") || lower.contains("peass-ng")
                    || lower.contains("windows local privilege")) {
                winpeas = true;
            }
            if (PRIVILEGE.matcher(text).find()) {
                privHits++;
                windowsish = true;
            }
            if (windowsMarker(text, lower)) {
                windowsish = true;
            }
            if (Signatures.anyMatch(signatures, text)) {
                sigHits++;
                windowsish = true;
            }
        }

        if (!winpeas && !windowsish) {
            return Detection.NONE;
        }
        int confidence = (winpeas ? 70 : 20)
                + Math.min(45, (sigHits + privHits) * 12)
                + (windowsish ? 10 : 0);
        String summary = winpeas ? "winPEAS / Windows privesc scan"
                : "Windows enumeration output";
        return Detection.of(Math.min(98, confidence), summary + ", " + (sigHits + privHits)
                + " signal" + (sigHits + privHits == 1 ? "" : "s"));
    }

    private static boolean windowsMarker(String text, String lower) {
        // Deliberately specific: a bare "C:\..." path is not enough (a plain directory listing
        // is not a privesc scan). These are tokens that only show up in privilege/service/enum
        // output, so they justify running the checklist engine.
        return lower.contains("nt authority\\")
                || lower.contains("builtin\\")
                || lower.contains("c:\\windows\\system32")
                || lower.contains("binary_path_name")
                || lower.contains("service_name")
                || lower.contains("alwaysinstallelevated")
                || lower.startsWith("privilege name");
    }

    private static boolean looksLikeLinpeas(Document doc) {
        for (Document.Line line : doc.contentLines()) {
            String lower = Signatures.clean(line.text()).toLowerCase();
            if (lower.contains("linpeas") || lower.contains("linux privilege escalation")
                    || lower.contains("linux local privilege")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table privileges = Kb.table("windows_privileges");
        Table groups = Kb.table("windows_groups");

        List<Finding> findings = new ArrayList<>();
        Set<String> seenPriv = new LinkedHashSet<>();
        Set<String> seenGroup = new LinkedHashSet<>();
        boolean winpeas = false;

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            String lower = text.toLowerCase();
            if (lower.contains("winpeas") || lower.contains("peass-ng")) {
                winpeas = true;
            }

            // token privileges
            Matcher priv = PRIVILEGE.matcher(text);
            while (priv.find()) {
                String name = priv.group();
                if (seenPriv.add(name.toLowerCase())) {
                    findings.add(assessPrivilege(name, text, line.number(), privileges));
                }
            }

            // privileged groups (only on lines that look like a groups/ACL listing)
            if (isGroupContext(lower)) {
                Matcher gm = GROUP_LINE.matcher(text);
                while (gm.find()) {
                    assessGroup(gm.group(2).strip(), text, line.number(), groups, seenGroup)
                            .ifPresent(findings::add);
                }
            }
        }

        // signatures - the shared engine, deduped by id
        findings.addAll(Signatures.scan(Signatures.load("windows_signatures"), doc));

        if (findings.isEmpty()) {
            findings.add(Finding.of(Severity.INFO, "windows", "Windows output, nothing flagged",
                    "This looks like Windows enumeration output, but none of the checklist "
                    + "signatures matched. Either it is clean, or it holds something not yet in the "
                    + "knowledge base - scan it by eye and consider adding a signature row.",
                    "", 0).note("signatures live in data/windows_signatures.tsv"));
        } else if (winpeas) {
            findings.add(Finding.of(Severity.INFO, "winpeas", "winPEAS run recognised",
                    "Findings below are grouped by what they are. winPEAS colours lines by interest; "
                    + "this adds what each one means and where to take it, per the HackTricks Windows "
                    + "privesc checklist.", "", 0));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assessPrivilege(String name, String evidence, int line, Table privileges) {
        Row row = privileges.first(name);
        boolean enabled = evidence.toLowerCase().contains("enabled");
        boolean disabled = evidence.toLowerCase().contains("disabled");
        Severity severity;
        String technique;
        String detail;
        if (row != null) {
            severity = Severity.parse(row.get("severity"), Severity.NOTICE);
            technique = row.get("technique");
            detail = row.get("description");
        } else {
            severity = Severity.NOTICE;
            technique = "-";
            detail = "A token privilege not in windows_privileges.tsv. Look it up - some are "
                    + "escalation primitives. Add a row so it is explained next time.";
        }
        Finding finding = Finding.of(severity, name,
                "token privilege" + (severity.atLeast(Severity.WARN) ? " - escalation primitive" : ""),
                detail, evidence, line);
        if (!technique.isEmpty() && !technique.equals("-")) {
            finding = finding.note("technique: " + technique);
        }
        if (enabled) {
            finding = finding.note("state: Enabled");
        } else if (disabled && severity.isAnomaly()) {
            finding = finding.note("state: Disabled here - but a process holding a privilege can "
                    + "usually enable it, so still treat it as available");
        }
        return finding;
    }

    private Optional<Finding> assessGroup(String group, String evidence, int line,
                                          Table groups, Set<String> seen) {
        Row row = groups.first(group);
        if (row == null) {
            return Optional.empty();   // unknown group name - not necessarily a group at all
        }
        Severity severity = Severity.parse(row.get("severity"), Severity.OK);
        if (severity == Severity.OK || !seen.add(group.toLowerCase())) {
            return Optional.empty();   // benign, or already reported
        }
        Finding finding = Finding.of(severity, "group: " + group, "privileged group membership",
                row.get("description"), evidence, line);
        if (row.has("technique") && !row.get("technique").equals("-")) {
            finding = finding.note("technique: " + row.get("technique"));
        }
        return Optional.of(finding);
    }

    private static boolean isGroupContext(String lower) {
        return lower.contains("\\") && (lower.contains("group") || lower.contains("alias")
                || lower.contains("well-known") || lower.contains("s-1-")
                || lower.contains("mandatory") || lower.contains("builtin")
                || lower.contains("enabled by default") || lower.contains("nt authority"));
    }
}
