package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;
import silverdetector.core.Table;
import silverdetector.detect.PermEntries.Entry;

/**
 * SUID (4000) and SGID (2000) hunts: {@code find / -perm -4000}, {@code -perm -2000},
 * {@code -perm /6000} and friends.
 *
 * <p>Every path is answered in one of four ways:
 * <ul>
 *   <li>in {@code data/suid_known.tsv} with matching bits - normal, and the row says what it
 *       is for</li>
 *   <li>in {@code data/suid_known.tsv} with <em>different</em> bits - the packaged default has
 *       been changed</li>
 *   <li>in {@code data/gtfobins.tsv} - a binary that hands out a root shell when it is SUID</li>
 *   <li>in neither - unknown, which on a stock install is the interesting case</li>
 * </ul>
 */
public final class SetuidDetector implements Detector {

    @Override
    public String id() {
        return "setuid";
    }

    @Override
    public String name() {
        return "SUID / SGID binaries (4000 / 2000)";
    }

    @Override
    public String accepts() {
        return "find / -perm -4000 (or -2000, /6000) output: bare paths, -ls, ls -l or '%m %p'";
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Entry> entries = PermEntries.parse(doc);
        if (entries.isEmpty()) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        long matched = entries.stream().map(Entry::line).distinct().count();
        int ratio = (int) (100L * matched / lines);

        long withSetid = entries.stream().filter(e -> e.suid() || e.sgid()).count();
        long systemPaths = entries.stream().filter(e -> isSystemPath(e.path())).count();
        long knownBins = entries.stream().filter(this::isKnownBinary).count();

        int confidence = 20 + ratio / 3;
        if (withSetid > 0) {
            confidence += 45;                                   // mode string actually shows s/S
        }
        if (systemPaths * 2 >= entries.size()) {
            confidence += 15;                                   // mostly /usr, /bin, /sbin, /opt
        }
        if (knownBins > 0) {
            confidence += 15;                                   // names we recognise as setid-ish
        }
        if (withSetid == 0 && knownBins == 0 && systemPaths * 2 < entries.size()) {
            confidence -= 20;                                   // just a list of random paths
        }

        String shape = entries.stream().anyMatch(e -> !e.modeString().isEmpty())
                ? "path list with mode bits"
                : "plain path list";
        return Detection.of(Math.min(97, confidence), "%s, %d path%s",
                shape, entries.size(), entries.size() == 1 ? "" : "s");
    }

    private boolean isKnownBinary(Entry entry) {
        return Kb.table("suid_known").containsKey(entry.path())
                || Kb.table("gtfobins").containsKey(entry.basename());
    }

    private static boolean isSystemPath(String path) {
        return path.startsWith("/usr/") || path.startsWith("/bin/") || path.startsWith("/sbin/")
                || path.startsWith("/opt/") || path.startsWith("/lib/") || path.startsWith("/etc/")
                || path.startsWith("/var/");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table known = Kb.table("suid_known");
        Table gtfobins = Kb.table("gtfobins");

        List<Finding> findings = new ArrayList<>();
        for (Entry entry : PermEntries.parse(doc)) {
            findings.add(assess(entry, known, gtfobins));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assess(Entry entry, Table known, Table gtfobins) {
        Row knownRow = known.first(entry.path());
        Row gtfoRow = gtfobins.first(entry.basename());

        Severity severity;
        String label;
        String detail;
        String reason;

        if (entry.directory()) {
            return directoryFinding(entry, knownRow);
        }

        if (knownRow != null) {
            label = knownRow.get("purpose", entry.basename());
            detail = knownRow.get("description", "part of the standard set-id set");
            String expected = knownRow.get("bits", "suid").toLowerCase();
            boolean bitsMatch = !entry.bitsKnown() || bitsMatch(expected, entry);
            if (bitsMatch) {
                severity = Severity.parse(knownRow.get("severity"), Severity.OK);
                reason = "expected: this is part of the standard set-id set on a Linux install";
            } else {
                severity = Severity.WARN;
                reason = "mode changed: the packaged default is " + expected.toUpperCase()
                        + " but this file is " + entry.bitsLabel();
            }
            if (gtfoRow != null && entry.suid()) {
                // e.g. someone chmod u+s'd a binary that also happens to ship set-id somewhere.
                severity = severity.max(Severity.NOTICE);
                reason += "; note this binary is also a known escalation vector (see gtfobins.tsv)";
            }
        } else if (gtfoRow != null) {
            String risk = gtfoRow.get("risk", "privesc").toLowerCase();
            label = entry.basename() + " - known privilege-escalation vector";
            detail = gtfoRow.get("description", "GTFOBins lists this binary as exploitable when set-id.");
            if (entry.bitsKnown() && entry.sgid() && !entry.suid()) {
                severity = Severity.WARN;
                reason = "SGID on a GTFOBins binary: gives away the '" + safeGroup(entry)
                        + "' group, not root, but it is still an escalation step";
            } else {
                severity = risk.equals("limited") ? Severity.WARN : Severity.CRITICAL;
                reason = "not part of any stock set-id set, and this binary can be turned into "
                        + "a root shell or arbitrary root file access";
            }
        } else {
            label = entry.basename();
            detail = "Not in suid_known.tsv and not a known GTFOBins binary - so either a stock file "
                     + "this build does not list yet, or a custom set-id binary worth a real look. "
                     + "The two notes below settle both: whether a package shipped it, and what it "
                     + "actually runs.";
            severity = Severity.WARN;
            reason = "unknown set-id binary - not in the standard set this build knows about";
        }

        boolean unknown = knownRow == null && gtfoRow == null;

        Finding finding = Finding.of(severity, entry.path(), label, detail,
                entry.raw().strip(), entry.line());

        String writableRoot = WritableDirs.match(entry.path());
        if (writableRoot != null) {
            finding = finding.atLeast(Severity.CRITICAL)
                    .note("lives under " + writableRoot + ", where packages never install set-id "
                          + "binaries - treat as a planted backdoor until proven otherwise");
        }

        if (!reason.isEmpty()) {
            finding = finding.note(reason);
        }
        if (unknown) {
            finding = addVerificationNotes(finding, entry);
        }
        if (entry.bitsKnown()) {
            String bits = entry.bitsLabel();
            String mode = entry.modeString().isEmpty() ? entry.octal() : entry.modeString();
            finding = finding.note("bits: " + bits + (mode.isEmpty() ? "" : " (" + mode + ")"));
        } else {
            finding = finding.note("the paste carries no mode bits, so this was taken at face "
                                   + "value as a set-id hit");
        }
        if (!entry.owner().isEmpty()) {
            String ownership = "owner: " + entry.owner()
                    + (entry.group().isEmpty() ? "" : ":" + entry.group());
            if (entry.suid() && !entry.owner().equals("root")) {
                ownership += " - SUID to a non-root user, so it grants that user's rights";
            }
            finding = finding.note(ownership);
        }
        return finding;
    }

    private Finding directoryFinding(Entry entry, Row knownRow) {
        String label = knownRow != null ? knownRow.get("purpose", "directory") : "directory";
        Severity severity = Severity.OK;
        String detail;
        if (entry.sgid()) {
            detail = "SGID directory: files created inside inherit the directory's group instead "
                     + "of the creator's. Normal for shared spool and mail directories.";
        } else if (entry.sticky()) {
            detail = "Sticky directory: anyone can write, but only the owner can delete their own "
                     + "files. Normal for /tmp and /var/tmp.";
        } else {
            detail = "Directory picked up by the search.";
            severity = Severity.INFO;
        }
        if (knownRow != null && knownRow.has("description")) {
            detail = knownRow.get("description");
        } else if (entry.sgid() && !isSystemPath(entry.path())) {
            severity = Severity.NOTICE;
            detail += " This one is outside the usual system paths - check who owns the group.";
        }
        return Finding.of(severity, entry.path(), label, detail, entry.raw().strip(), entry.line())
                .note("bits: " + entry.bitsLabel()
                      + (entry.modeString().isEmpty() ? "" : " (" + entry.modeString() + ")"));
    }

    /**
     * The two questions a wall of "unknown SUID" WARNs leaves you with: is it really not a
     * distro default, and how do I tell whether it hands me a privilege. Answers both with
     * commands built from this exact path, plus - if it is set-id to a group that is worth
     * something - what that group buys you (reused straight from {@code groups.tsv}).
     */
    private Finding addVerificationNotes(Finding finding, Entry entry) {
        String gain = privilegeGain(entry);
        if (gain != null) {
            finding = finding.note(gain);
        }
        String p = entry.path();
        finding = finding.note("is it truly non-default? ask the package DB who owns it: "
                + "dpkg -S " + p + " (Debian/Ubuntu/Kali) · rpm -qf " + p + " (RHEL/Fedora) · "
                + "pacman -Qo " + p + " (Arch). If no package owns it, it did not ship with the "
                + "distro - treat it as planted. If one does, it is that package's default, so the "
                + "bit is only interesting if the program itself is (next note).");
        finding = finding.note("check the priv: strings -n 6 " + p + " | grep -iE "
                + "'/bin/|/tmp|system|exec|popen|setuid|chmod|cp |env|PATH=' shows what it runs; "
                + "ltrace -f " + p + " (or strace -f -e trace=execve,openat) shows the commands and "
                + "files it touches when you run it. A command it calls by bare name, or any file or "
                + "library you can write that it opens, is the hijack - that is the escalation.");
        return finding;
    }

    /**
     * What running this binary hands you beyond your own rights: the owner's identity if it is
     * SUID to a non-root account whose files matter, and the group's powers if it is SGID to a
     * group {@code groups.tsv} rates as sensitive (shadow -> the hashes, disk -> the raw disk,
     * ...). Returns {@code null} when there is nothing special to say.
     */
    private static String privilegeGain(Entry entry) {
        if (!entry.sgid() || entry.group().isEmpty()) {
            return null;
        }
        Row groupRow = Kb.table("groups").first(entry.group());
        if (groupRow == null
                || !Severity.parse(groupRow.get("severity"), Severity.OK).atLeast(Severity.NOTICE)) {
            return null;
        }
        String note = "runs set-GID '" + entry.group() + "' - " + groupRow.get("description", "");
        String exploit = groupRow.get("exploit", "-");
        if (!exploit.isEmpty() && !exploit.equals("-")) {
            note += "  (try: " + exploit + ")";
        }
        return note;
    }

    private static boolean bitsMatch(String expected, Entry entry) {
        boolean wantSuid = expected.contains("suid") || expected.contains("4");
        boolean wantSgid = expected.contains("sgid") || expected.contains("2");
        if (expected.contains("any")) {
            return true;
        }
        return wantSuid == entry.suid() && wantSgid == entry.sgid();
    }

    private static String safeGroup(Entry entry) {
        return entry.group().isEmpty() ? "file's" : entry.group();
    }
}
