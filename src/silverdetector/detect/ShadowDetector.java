package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Row;
import silverdetector.core.Severity;

/**
 * {@code /etc/shadow}: the password hashes themselves.
 *
 * <p>Each line is {@code name:hash:lastchange:min:max:warn:inactive:expire:reserved} (9 fields).
 * Just having this file's contents is significant - it is normally {@code root:shadow 0640} or
 * stricter, so reading it means you already reached root, or it is exposed and that is the
 * finding.
 *
 * <p>Per account the detector reports: no password at all (empty hash), a locked account
 * ({@code *} / {@code !}), or a live hash - and for a live hash, which algorithm it is, whether
 * that algorithm is weak, and the exact hashcat/john mode to crack it. That last part is the
 * "learn while you work" bit: it turns "I found a hash" into a command you can run.
 */
public final class ShadowDetector implements Detector {

    private record Shadow(int line, String raw, String name, String hash) {
    }

    @Override
    public String id() {
        return "shadow";
    }

    @Override
    public String name() {
        return "/etc/shadow password hashes";
    }

    @Override
    public String accepts() {
        return "cat /etc/shadow (name:hash:lastchange:min:max:warn:inactive:expire:)";
    }

    @Override
    public int order() {
        return 55;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Shadow> rows = parse(doc);
        if (rows.isEmpty()) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        int ratio = (int) (100L * rows.size() / lines);
        // A field-2 that is a hash or a lock marker is what separates shadow from any other
        // 9-colon data, so weight the ones that actually look like password fields.
        long passwordish = rows.stream()
                .filter(r -> r.hash().isEmpty() || CryptHash.isHash(r.hash()) || CryptHash.isLocked(r.hash()))
                .count();
        int confidence = Math.min(98, 50 + ratio / 2 + (int) (passwordish * 30 / rows.size()));
        return Detection.of(confidence, "/etc/shadow, %d entr%s",
                rows.size(), rows.size() == 1 ? "y" : "ies");
    }

    private List<Shadow> parse(Document doc) {
        List<Shadow> out = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            String[] f = text.split(":", -1);
            if (f.length != 9 || f[0].isEmpty()) {
                continue;
            }
            // Reject 9-field lines that are clearly not shadow: the ageing fields are numeric
            // or empty, and field 2 is a hash, a lock marker, or empty.
            if (!ageingLooksRight(f)) {
                continue;
            }
            out.add(new Shadow(line.number(), text, f[0], f[1]));
        }
        return out;
    }

    private static boolean ageingLooksRight(String[] f) {
        for (int i = 2; i <= 7; i++) {
            String v = f[i];
            if (!v.isEmpty() && !v.chars().allMatch(Character::isDigit)) {
                return false;
            }
        }
        String pw = f[1];
        return pw.isEmpty() || CryptHash.isHash(pw) || CryptHash.isLocked(pw) || pw.equals("!!");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Shadow> rows = parse(doc);
        List<Finding> findings = new ArrayList<>();

        findings.add(context(rows));
        for (Shadow row : rows) {
            findings.add(assess(row));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    /** One header finding: reading this file at all is the first thing worth saying. */
    private Finding context(List<Shadow> rows) {
        return Finding.of(Severity.NOTICE, "/etc/shadow", "you are reading the shadow file",
                "/etc/shadow is normally mode 0640 root:shadow or stricter. Having its contents "
                + "means you already have root-equivalent read access, or the file is exposed - "
                + "either way, every live hash below is now an offline cracking target.",
                "", 0)
                .note(rows.size() + " account entr" + (rows.size() == 1 ? "y" : "ies") + " parsed")
                .note("dump these with 'unshadow /etc/passwd /etc/shadow' before feeding john");
    }

    private Finding assess(Shadow row) {
        String hash = row.hash();
        Severity severity;
        String label;
        String detail;
        String note;

        if (hash.isEmpty()) {
            severity = Severity.CRITICAL;
            label = "no password set";
            detail = "The hash field is empty, so this account authenticates with no password. "
                    + "If it also has a login shell, it is an open door.";
            note = "try logging in as '" + row.name() + "' with an empty password";
        } else if (hash.equals("!") || hash.equals("!!") || hash.equals("*") || hash.startsWith("!$")
                || hash.startsWith("*")) {
            severity = Severity.OK;
            label = "locked / no password login";
            detail = hash.startsWith("!$")
                    ? "Locked: the '!' prefix disables password login even though an old hash is "
                      + "still stored behind it. Normal for accounts that only log in by SSH key "
                      + "or not at all."
                    : "Locked or disabled for password login ('" + hash + "'). Normal for daemon "
                      + "accounts. It does not block SSH keys or su-from-root.";
            note = "no crackable password (login by other means may still work)";
        } else if (CryptHash.isHash(hash)) {
            Row format = CryptHash.describe(hash);
            if (format == null) {
                severity = Severity.NOTICE;
                label = "password hash (unrecognised algorithm)";
                detail = "A live password hash whose algorithm marker is not in hash_formats.tsv. "
                        + "Identify it (hashid / hashcat --identify) before cracking.";
                note = "algorithm id '" + CryptHash.algorithmId(hash) + "' - add it to "
                        + "hash_formats.tsv to get a cracking mode here";
            } else {
                severity = Severity.parse(format.get("severity"), Severity.OK);
                String strong = severity.atLeast(Severity.WARN) ? "weak" : "strong";
                label = "password hash - " + format.get("algo") + " (" + strong + ")";
                detail = format.get("description");
                String hint = CryptHash.crackHint(format);
                note = hint.isEmpty() ? "live hash - crack offline with a wordlist" : hint;
            }
        } else {
            severity = Severity.NOTICE;
            label = "unexpected password field";
            detail = "Field 2 is neither a recognised hash nor a lock marker: '" + hash + "'.";
            note = "inspect this by hand";
        }

        return Finding.of(severity, row.name(), label, detail, row.raw(), row.line()).note(note);
    }
}
