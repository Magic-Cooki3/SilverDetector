package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;
import silverdetector.core.Table;

/**
 * {@code /etc/passwd}: who can log in, who is root, and whether anything has been slipped in.
 *
 * <p>Each line is {@code name:password:uid:gid:gecos:home:shell}. The password field is normally
 * {@code x} (the real hash lives in shadow), so anything else there is the whole finding.
 *
 * <p>What a red-teamer reads this file for, and what the detector calls out:
 * <ul>
 *   <li>a second UID 0 account - root by another name, a classic persistence trick</li>
 *   <li>a password <em>hash</em> sitting in this world-readable file - crack it offline</li>
 *   <li>an empty password field - log in as that account with no password at all</li>
 *   <li>a system account that has been given an interactive shell - a hidden way back in</li>
 *   <li>the human accounts - the credentials worth targeting</li>
 * </ul>
 */
public final class PasswdDetector implements Detector {

    /** UID boundary between distro/system accounts and human logins (login.defs UID_MIN). */
    private static final int HUMAN_UID_FLOOR = 1000;
    private static final int NOBODY_UID = 65534;

    private record Acct(int line, String raw, String name, String pass,
                        long uid, long gid, String gecos, String home, String shell) {
    }

    @Override
    public String id() {
        return "passwd";
    }

    @Override
    public String name() {
        return "/etc/passwd accounts";
    }

    @Override
    public String accepts() {
        return "cat /etc/passwd (name:x:uid:gid:gecos:home:shell)";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Acct> accounts = parse(doc);
        if (accounts.isEmpty()) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        int ratio = (int) (100L * accounts.size() / lines);
        boolean hasRoot = accounts.stream().anyMatch(a -> a.uid() == 0);
        int confidence = Math.min(97, 45 + ratio / 2 + (hasRoot ? 20 : 0));
        return Detection.of(confidence, "/etc/passwd, %d account%s",
                accounts.size(), accounts.size() == 1 ? "" : "s");
    }

    /** Parses only well-formed 7-field lines; anything else belongs to another detector. */
    private List<Acct> parse(Document doc) {
        List<Acct> out = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            String[] f = text.split(":", -1);
            if (f.length != 7 || !isUnsigned(f[2]) || !isUnsigned(f[3])) {
                continue;
            }
            // Reject 7-colon lines that are not passwd: a username has no spaces, and the shell
            // field is empty or an absolute path. This keeps out things like nmap's
            // "MAC Address: 08:00:27:A5:11:9C (...)" that happen to split into seven fields.
            if (!isUsername(f[0]) || !isShellField(f[6])) {
                continue;
            }
            out.add(new Acct(line.number(), text, f[0], f[1],
                    Long.parseLong(f[2]), Long.parseLong(f[3]), f[4], f[5], f[6]));
        }
        return out;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Acct> accounts = parse(doc);
        Table known = Kb.table("system_users");

        Map<Long, Integer> uidCounts = new HashMap<>();
        for (Acct acct : accounts) {
            uidCounts.merge(acct.uid(), 1, Integer::sum);
        }

        List<Finding> findings = new ArrayList<>();
        for (Acct acct : accounts) {
            findings.add(assess(acct, known, uidCounts));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingLong(f -> uidOf(f, accounts)));
        return findings;
    }

    private static long uidOf(Finding f, List<Acct> accounts) {
        for (Acct a : accounts) {
            if (a.name().equals(f.subject())) {
                return a.uid();
            }
        }
        return Long.MAX_VALUE;
    }

    private Finding assess(Acct acct, Table known, Map<Long, Integer> uidCounts) {
        Row row = known.first(acct.name());
        boolean interactive = interactiveShell(acct.shell());
        boolean human = acct.uid() >= HUMAN_UID_FLOOR && acct.uid() < NOBODY_UID;

        Severity severity;
        String label;
        String detail;
        String reason;

        if (acct.uid() == 0) {
            if (acct.name().equals("root")) {
                severity = Severity.OK;
                label = "superuser (root)";
                detail = "UID 0, the administrator account. Expected, and expected to have a shell.";
                reason = "the one account that is supposed to be UID 0";
            } else {
                severity = Severity.CRITICAL;
                label = "UID 0 account - root by another name";
                detail = "This account has UID 0, so the kernel treats it as root regardless of "
                        + "its name. A second UID 0 account is a classic backdoor: it survives a "
                        + "root password change and hides in plain sight.";
                reason = "non-root account with UID 0 - full administrative rights";
            }
        } else if (human) {
            severity = Severity.INFO;
            label = "human login account";
            detail = "A normal user account (UID " + acct.uid() + "). These are the credentials "
                    + "worth targeting: check for password reuse, SSH keys under " + acct.home()
                    + "/.ssh, and sudo rights (sudo -l).";
            reason = "interactive user account";
        } else if (interactive && !isBenignShell(acct.shell())) {
            severity = Severity.WARN;
            label = (row != null ? row.get("purpose", "system account") : "system account")
                    + " with an interactive shell";
            detail = "A system account (UID " + acct.uid() + ") whose shell is " + acct.shell()
                    + ". System daemons should use nologin/false; a real shell here is a common "
                    + "way to hide a login, and a target if you can set its password.";
            reason = "service account that can be logged into";
        } else {
            severity = Severity.OK;
            label = row != null ? row.get("purpose", "system account") : "system account";
            detail = row != null && row.has("description")
                    ? row.get("description")
                    : "Unprivileged system account (UID " + acct.uid() + "), no interactive login.";
            reason = "expected non-login system account";
        }

        // The password field overrides almost everything: a hash or a blank here is the finding.
        Severity passwordSeverity = severity;
        String passwordNote = null;
        String field = acct.pass();
        if (field.isEmpty()) {
            passwordSeverity = Severity.CRITICAL;
            passwordNote = "empty password field: this account logs in with NO password. "
                    + "Try 'su - " + acct.name() + "' with an empty password.";
        } else if (CryptHash.isHash(field)) {
            passwordSeverity = Severity.CRITICAL;
            Row format = CryptHash.describe(field);
            String hint = CryptHash.crackHint(format);
            passwordNote = "a password HASH is stored in world-readable /etc/passwd"
                    + (format != null ? " (" + format.get("algo") + ")" : "")
                    + " - anyone who can read this file can crack it offline"
                    + (hint.isEmpty() ? "" : "; " + hint);
        } else if (!field.equals("x") && !CryptHash.isLocked(field)) {
            // "*" and "!" are locked; "x" is shadowed; anything else is unusual.
            passwordSeverity = passwordSeverity.max(Severity.NOTICE);
            passwordNote = "unusual password field '" + field + "' (expected 'x' for a shadowed "
                    + "account)";
        }

        Finding finding = Finding.of(passwordSeverity.max(severity), acct.name(), label, detail,
                acct.raw(), acct.line());
        finding = finding.note(reason);
        if (passwordNote != null) {
            finding = finding.note(passwordNote);
        }
        finding = finding.note("uid=" + acct.uid() + " gid=" + acct.gid()
                + " home=" + acct.home() + " shell=" + acct.shell());

        if (uidCounts.getOrDefault(acct.uid(), 0) > 1) {
            String note = "UID " + acct.uid() + " is shared by more than one account in this file "
                    + "- duplicate UIDs mean shared privileges and are almost never intentional";
            // The offending accounts (the extra ones) already carry their own severity; don't
            // escalate the legitimate root line just because a backdoor borrowed its UID.
            boolean canonicalRoot = acct.uid() == 0 && acct.name().equals("root");
            finding = canonicalRoot
                    ? finding.note(note)
                    : finding.atLeast(acct.uid() == 0 ? Severity.CRITICAL : Severity.WARN).note(note);
        }
        return finding;
    }

    /** A shell that actually gives a session, as opposed to nologin/false/sync. */
    private static boolean interactiveShell(String shell) {
        String s = shell.strip();
        if (s.isEmpty()) {
            return true;   // an empty shell field historically means /bin/sh
        }
        return !isBenignShell(s);
    }

    private static boolean isBenignShell(String shell) {
        String s = shell.strip();
        if (s.contains("nologin") || s.equals("/dev/null")) {
            return true;
        }
        String base = s.substring(s.lastIndexOf('/') + 1);
        return base.equals("false") || base.equals("true") || base.equals("sync")
                || base.equals("halt") || base.equals("shutdown");
    }

    private static boolean isUnsigned(String s) {
        return !s.isEmpty() && s.chars().allMatch(Character::isDigit);
    }

    /** A plausible account name: no whitespace, starts with a normal name character. */
    private static boolean isUsername(String s) {
        return s.matches("[A-Za-z0-9_][A-Za-z0-9_.$-]*");
    }

    /** The shell field is empty or an absolute path - never free text with spaces. */
    private static boolean isShellField(String s) {
        return s.isEmpty() || (s.startsWith("/") && !s.contains(" "));
    }
}
