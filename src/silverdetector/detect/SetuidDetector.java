package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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

    /** A directory where a distro legitimately keeps set-id binaries (so a standard binary found
     *  here at a non-canonical path is a variant, not an anomaly). Excludes /opt, /usr/local and
     *  the writable dirs, which stay worth a second look. */
    private static boolean isCanonicalSystemBin(String path) {
        return path.startsWith("/usr/bin/") || path.startsWith("/bin/")
                || path.startsWith("/usr/sbin/") || path.startsWith("/sbin/")
                || path.startsWith("/usr/lib/") || path.startsWith("/lib/")
                || path.startsWith("/usr/lib64/") || path.startsWith("/lib64/")
                || path.startsWith("/usr/libexec/");
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
        Map<String, Row> knownByBase = knownByBasename(known);

        List<Finding> findings = new ArrayList<>();
        List<Entry> snapImages = new ArrayList<>();
        for (Entry entry : PermEntries.parse(doc)) {
            // A set-id copy of a standard binary inside a read-only snap image is never the
            // vector - and there can be dozens (one per snap revision). Fold them into a single
            // line instead of drowning the report. Anything with an unfamiliar name still gets
            // assessed on its own, even inside a snap.
            if (!entry.directory() && isSnapImage(entry.path())
                    && knownByBase.containsKey(entry.basename())) {
                snapImages.add(entry);
            } else {
                findings.add(assess(entry, known, gtfobins, knownByBase));
            }
        }
        if (!snapImages.isEmpty()) {
            findings.add(snapSummary(snapImages));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    /** basename -&gt; the canonical row that owns it, so a standard binary is recognised even at
     *  a path the table doesn't list verbatim (usr-merge, multiarch, a snap or bundled copy). */
    private static Map<String, Row> knownByBasename(Table known) {
        Map<String, Row> map = new HashMap<>();
        for (Row row : known.rows()) {
            String path = row.get("path", "");
            int slash = path.lastIndexOf('/');
            String base = slash >= 0 ? path.substring(slash + 1) : path;
            if (!base.isEmpty()) {
                map.putIfAbsent(base, row);            // first row wins = the canonical path
            }
        }
        return map;
    }

    private static boolean isSnapImage(String path) {
        return path.startsWith("/snap/") || path.startsWith("/var/lib/snapd/snap/");
    }

    /** "core 11420" from /snap/core/11420/usr/bin/su - the snap name and its revision. */
    private static String snapRoot(String path) {
        String[] p = path.split("/");
        if (p.length >= 4 && "snap".equals(p[1])) {
            return p[2] + " " + p[3];
        }
        if (p.length >= 6 && "var".equals(p[1]) && "snapd".equals(p[3])) {
            return p[4] + " " + p[5];
        }
        return "snap";
    }

    private Finding snapSummary(List<Entry> folded) {
        Map<String, Integer> roots = new LinkedHashMap<>();
        int firstLine = Integer.MAX_VALUE;
        for (Entry entry : folded) {
            roots.merge(snapRoot(entry.path()), 1, Integer::sum);
            firstLine = Math.min(firstLine, entry.line());
        }
        String rootList = roots.entrySet().stream()
                .map(e -> e.getKey() + " (" + e.getValue() + ")")
                .collect(Collectors.joining(", "));
        String detail = "Packaged copies of standard set-id binaries (su, sudo, mount, passwd, ...) "
                + "inside read-only snap squashfs images. A file inside a mounted snap can't be "
                + "modified and each runs under snap confinement, so none of these is a local-privesc "
                + "vector - they are the same binaries you already see at their real paths. Folded "
                + "into one line so they don't bury the binaries that matter.";
        return Finding.of(Severity.INFO, "/snap/*",
                        folded.size() + " set-id binaries inside read-only snap images",
                        detail, "", firstLine == Integer.MAX_VALUE ? 0 : firstLine)
                .note("snap revisions here: " + rootList)
                .note("drop them from the hunt next time: "
                        + "find / -perm -4000 -type f 2>/dev/null | grep -v '^/snap/'");
    }

    private Finding assess(Entry entry, Table known, Table gtfobins, Map<String, Row> knownByBase) {
        Row knownRow = known.first(entry.path());
        Row gtfoRow = gtfobins.first(entry.basename());

        Severity severity;
        String label;
        String detail;
        String reason;
        boolean wantVerify = false;

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
        } else if (knownByBase.containsKey(entry.basename())) {
            // The name is a standard set-id binary, but this exact path is not the packaged one.
            // Where it sits decides everything: a system dir is just a usr-merge/multiarch/bundled
            // copy; a writable dir means someone planted a look-alike; anywhere else, verify.
            Row base = knownByBase.get(entry.basename());
            String canonical = base.get("path", entry.path());
            detail = base.get("description", "");
            if (WritableDirs.match(entry.path()) != null) {
                severity = Severity.CRITICAL;
                label = entry.basename() + " - look-alike in a writable path";
                reason = "a binary named like the standard '" + entry.basename() + "' (" + canonical
                        + ") but sitting where packages never put one - this is not the packaged "
                        + "binary; treat it as planted until you confirm otherwise";
                wantVerify = true;
            } else if (isCanonicalSystemBin(entry.path())) {
                severity = Severity.parse(base.get("severity"), Severity.OK);
                label = base.get("purpose", entry.basename()) + " (standard binary, variant path)";
                reason = "same binary as " + canonical + ", just at a different system path "
                        + "(usr-merge, a multiarch dir, or a bundled copy) - not an anomaly";
            } else {
                severity = Severity.NOTICE;
                label = base.get("purpose", entry.basename()) + " (name matches a standard binary)";
                reason = "shares its name with the standard '" + entry.basename() + "' (" + canonical
                        + ") but sits at an unusual path - confirm it really is that binary";
                wantVerify = true;
            }
        } else {
            label = entry.basename() + " - custom set-id binary (no package owns it here)";
            detail = "This name is in neither the standard set-id set this build knows nor GTFOBins, "
                     + "so on a stock box it is the odd one out - a hand-placed set-id binary is the "
                     + "classic intended-privesc. The two notes below settle it: whether a package "
                     + "shipped it, and what it actually runs.";
            severity = Severity.WARN;
            reason = "custom set-id binary - not part of any standard or known-exploitable set";
            wantVerify = true;
        }

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
        if (wantVerify) {
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
