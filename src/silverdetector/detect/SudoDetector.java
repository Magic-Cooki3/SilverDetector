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
 * {@code sudo -l}: what the current user is allowed to run as someone else. The single most
 * valuable privilege-escalation enumeration output there is, which is why it gets the most
 * detailed reader.
 *
 * <p>It calls out the obvious win ({@code (ALL) ALL}), the binary wins (a command that GTFOBins
 * can turn into a root shell), the environment wins ({@code env_keep} that lets you inject
 * {@code LD_PRELOAD}), the no-password entries, and the version-specific ones (Baron Samedit
 * and friends). For each, it says why it escalates and what to do next - the point being that a
 * learner reads the finding and knows the move, not just that "something is wrong".
 */
public final class SudoDetector implements Detector {

    // (runas) [TAG: ...] command[, command...]
    private static final Pattern SPEC = Pattern.compile("^\\(([^)]*)\\)\\s*(.*)$");
    private static final Pattern TAG = Pattern.compile("^([A-Z_]+):\\s*(.*)$");
    private static final Pattern OPTION = Pattern.compile("^([A-Za-z_]+=\\S+)\\s*(.*)$");
    private static final Pattern VERSION = Pattern.compile("(?i)sudo version\\s+(\\d+\\.\\d+\\.\\d+(?:p\\d+)?)");

    // Environment variables that turn "keep this variable" into arbitrary code execution.
    private static final List<String> INJECTABLE_ENV = List.of(
            "LD_PRELOAD", "LD_LIBRARY_PATH", "PERL5LIB", "PERLLIB", "PERL5OPT",
            "PYTHONPATH", "PYTHONINSPECT", "RUBYLIB", "RUBYOPT", "BASH_ENV", "ENV",
            "GEM_PATH", "NODE_OPTIONS", "TCL_LIBRARY");

    @Override
    public String id() {
        return "sudo";
    }

    @Override
    public String name() {
        return "sudo rights (sudo -l)";
    }

    @Override
    public String accepts() {
        return "sudo -l output (Defaults entries and the 'may run the following commands' list)";
    }

    @Override
    public int order() {
        return 15;
    }

    @Override
    public Detection sniff(Document doc) {
        boolean mayRun = false;
        boolean defaults = false;
        boolean negative = false;
        int specs = 0;
        for (Document.Line line : doc.contentLines()) {
            String lower = line.text().toLowerCase();
            if (lower.contains("may run the following commands")) {
                mayRun = true;
            }
            if (lower.contains("matching defaults entries")) {
                defaults = true;
            }
            if (lower.contains("is not in the sudoers file") || lower.contains("not allowed to run sudo")
                    || lower.contains("may not run sudo")) {
                negative = true;
            }
            if (SPEC.matcher(line.text().strip()).matches()) {
                specs++;
            }
        }
        if (!mayRun && !defaults && !negative && specs == 0) {
            return Detection.NONE;
        }
        int confidence = 0;
        if (mayRun) {
            confidence += 65;
        }
        if (defaults) {
            confidence += 20;
        }
        if (negative) {
            confidence += 60;
        }
        confidence += Math.min(20, specs * 8);
        String summary = negative && specs == 0
                ? "sudo -l: user has no sudo rights"
                : "sudo -l output, " + specs + " command rule" + (specs == 1 ? "" : "s");
        return Detection.of(Math.min(97, confidence), summary);
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table gtfobins = Kb.table("gtfobins");
        List<Finding> findings = new ArrayList<>();
        SudoVersion version = null;
        StringBuilder defaultsText = new StringBuilder();
        boolean inDefaults = false;
        boolean sawRules = false;

        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            String lower = text.toLowerCase();

            Matcher ver = VERSION.matcher(text);
            if (ver.find()) {
                version = SudoVersion.parse(ver.group(1));
                continue;
            }
            if (lower.contains("is not in the sudoers file") || lower.contains("not allowed to run sudo")
                    || lower.contains("may not run sudo")) {
                findings.add(Finding.of(Severity.INFO, "sudo", "no sudo rights",
                        "This user is not in sudoers (or is denied). No sudo escalation from here - "
                        + "look at SUID, capabilities, cron and group membership instead.", text, line.number()));
                continue;
            }
            if (lower.startsWith("matching defaults entries")) {
                inDefaults = true;
                int colon = text.indexOf(':');
                if (colon >= 0 && colon + 1 < text.length()) {
                    defaultsText.append(' ').append(text.substring(colon + 1));
                }
                continue;
            }
            if (lower.contains("may run the following commands")) {
                inDefaults = false;
                sawRules = true;
                continue;
            }

            Matcher spec = SPEC.matcher(text);
            if (spec.matches()) {
                inDefaults = false;
                findings.addAll(assessSpec(spec.group(1).strip(), spec.group(2).strip(), text,
                        line.number(), gtfobins, version));
                continue;
            }
            if (inDefaults && !text.isEmpty()) {
                defaultsText.append(' ').append(text);
            }
        }

        findings.addAll(assessDefaults(defaultsText.toString(), version));
        if (version != null) {
            findings.addAll(version.findings());
        }
        if (findings.isEmpty() && sawRules) {
            findings.add(Finding.of(Severity.NOTICE, "sudo", "rules present but not parsed",
                    "sudo -l listed rules, but none matched a shape this detector understands - "
                    + "read them by hand.", "", 0));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingInt(Finding::line));
        return findings;
    }

    private List<Finding> assessSpec(String runasRaw, String rest, String evidence, int line,
                                     Table gtfobins, SudoVersion version) {
        List<Finding> out = new ArrayList<>();

        String userPart = runasRaw.contains(":") ? runasRaw.substring(0, runasRaw.indexOf(':')) : runasRaw;
        String runasLabel = runasRaw.isBlank() ? "root" : runasRaw;
        boolean runsAsRoot = mentionsRoot(userPart);
        boolean negatedRunas = runasRaw.contains("!");

        Set<String> tags = new LinkedHashSet<>();
        String commands = stripTags(rest, tags);
        boolean nopasswd = tags.contains("NOPASSWD");
        boolean setenv = tags.contains("SETENV");

        for (String raw : commands.split("\\s*,\\s*")) {
            String command = raw.strip();
            if (command.isEmpty()) {
                continue;
            }
            out.add(assessCommand(command, runasLabel, runsAsRoot, negatedRunas, nopasswd, setenv,
                    evidence, line, gtfobins, version));
        }
        if (out.isEmpty()) {
            out.add(Finding.of(Severity.NOTICE, "sudo " + runasLabel, "unreadable rule",
                    "A sudo rule for " + runasLabel + " that produced no command - inspect it by hand.",
                    evidence, line));
        }
        return out;
    }

    private Finding assessCommand(String command, String runasLabel, boolean runsAsRoot,
                                  boolean negatedRunas, boolean nopasswd, boolean setenv,
                                  String evidence, int line, Table gtfobins, SudoVersion version) {
        boolean excluded = command.startsWith("!");
        String path = excluded ? command.substring(1) : command;
        String program = path.split("\\s+")[0];
        String base = basename(program);
        boolean wildcard = path.contains("*");

        Severity severity;
        String label;
        String detail;
        String next;

        if (excluded) {
            severity = Severity.INFO;
            label = "explicitly denied: " + base;
            detail = "This command is subtracted from a broader grant. Denylists are fragile - a "
                    + "different path to the same binary, or a wrapper, often slips past them.";
            next = "check whether the same effect is reachable another way";
        } else if (command.equalsIgnoreCase("ALL")) {
            if (runsAsRoot) {
                severity = Severity.CRITICAL;
                label = "run ANY command as " + runasLabel;
                detail = "Unrestricted sudo. This is a root shell whenever you want one.";
                next = "sudo -i    (or: sudo su -)";
            } else {
                severity = Severity.WARN;
                label = "run any command as " + runasLabel;
                detail = "You can run anything as " + runasLabel + ". Not root directly, but a strong "
                        + "pivot - especially if that user owns services, keys or a database.";
                next = "sudo -u " + firstUser(runasLabel) + " -i";
            }
        } else if (base.equals("sudoedit") || program.endsWith("sudoedit")) {
            severity = Severity.NOTICE;
            label = "sudoedit as " + runasLabel;
            detail = "Edits a file as " + runasLabel + ". Safe in principle, but the target path and "
                    + "the sudo version matter (CVE-2023-22809 let an attacker open extra files via "
                    + "the EDITOR variable).";
            next = "check the sudo version against CVE-2023-22809";
        } else {
            Row gtfo = gtfobins.first(base);
            if (gtfo != null) {
                String risk = gtfo.get("risk", "privesc").toLowerCase();
                boolean strong = risk.equals("privesc") || risk.equals("write");
                severity = runsAsRoot ? (strong ? Severity.CRITICAL : Severity.WARN)
                                      : (strong ? Severity.WARN : Severity.NOTICE);
                label = base + " via sudo - GTFOBins escalation";
                detail = gtfo.get("description", "GTFOBins lists a way to run commands or read/write "
                        + "files through this binary.")
                        + " Run through sudo, that happens as " + runasLabel + ".";
                next = "see GTFOBins entry for '" + base + "' (sudo section)"
                        + (runsAsRoot ? " - it yields a root shell" : "");
            } else if (wildcard) {
                severity = Severity.NOTICE;
                label = base + " with a wildcard argument";
                detail = "A fixed command with a '*' in it. Wildcards are where argument-injection "
                        + "lives: extra flags, an extra path, or shell metacharacters may do more "
                        + "than the rule intended.";
                next = "test what other arguments the '*' will accept";
            } else {
                severity = Severity.NOTICE;
                label = "custom command as " + runasLabel + ": " + base;
                detail = "A specific binary allowed via sudo. Check it for shell escapes, for a "
                        + "writable path (you could replace the binary), and for config or scripts "
                        + "it reads that you can influence.";
                next = "is '" + program + "' writable, or does it read a file you control?";
            }
        }

        Finding finding = Finding.of(severity, "sudo " + runasLabel + ": " + base, label, detail,
                evidence, line).note("next: " + next);

        if (nopasswd && severity.isAnomaly()) {
            finding = finding.note("NOPASSWD: no password required - this works even without the "
                    + "user's own password");
        }
        if (setenv) {
            finding = finding.note("SETENV: the rule lets you pass environment variables through - "
                    + "combine with LD_PRELOAD if the target is dynamically linked");
        }
        if (negatedRunas && !excluded) {
            finding = finding.atLeast(Severity.NOTICE).note("the runas spec contains a negation "
                    + "('!'): on sudo < 1.8.28 you can pass -u#-1 to run as root anyway "
                    + "(CVE-2019-14287)");
            if (version != null && version.runasNegationBypass()) {
                finding = finding.atLeast(Severity.WARN)
                        .note("this sudo version (" + version + ") is in the CVE-2019-14287 range");
            }
        }
        return finding;
    }

    private List<Finding> assessDefaults(String text, SudoVersion version) {
        List<Finding> out = new ArrayList<>();
        if (text.isBlank()) {
            return out;
        }
        String lower = text.toLowerCase();

        if (lower.contains("env_keep")) {
            List<String> risky = new ArrayList<>();
            for (String env : INJECTABLE_ENV) {
                if (text.contains(env)) {
                    risky.add(env);
                }
            }
            if (!risky.isEmpty()) {
                out.add(Finding.of(Severity.CRITICAL, "Defaults env_keep",
                        "dangerous variables preserved across sudo",
                        "sudo keeps " + String.join(", ", risky) + " from your environment. On a "
                        + "dynamically linked target you can point LD_PRELOAD (or the language path) "
                        + "at a library you wrote and get code execution as root.",
                        "", 0).note("next: build a small .so, export LD_PRELOAD, run a sudo-allowed "
                        + "binary"));
            }
        }
        if (lower.contains("!authenticate")) {
            out.add(Finding.of(Severity.WARN, "Defaults !authenticate", "no password ever required",
                    "This user runs sudo without authenticating at all. Every allowed command is "
                    + "one step away with no credential needed.", "", 0));
        }
        if (containsToken(lower, "pwfeedback")) {
            Finding f = Finding.of(Severity.NOTICE, "Defaults pwfeedback", "pwfeedback enabled",
                    "sudo echoes asterisks for the password. On 1.7.1-1.8.30 this was a stack "
                    + "overflow exploitable to root (CVE-2019-18634).", "", 0);
            if (version != null && version.pwfeedbackVulnerable()) {
                f = f.atLeast(Severity.CRITICAL).note("this sudo version (" + version + ") is in the "
                        + "CVE-2019-18634 range");
            }
            out.add(f);
        }
        if (containsToken(lower, "!env_reset")) {
            out.add(Finding.of(Severity.WARN, "Defaults !env_reset", "environment not reset",
                    "sudo passes your whole environment through instead of scrubbing it. Widens the "
                    + "door for LD_PRELOAD-style tricks.", "", 0));
        } else if (containsToken(lower, "setenv")) {
            out.add(Finding.of(Severity.NOTICE, "Defaults setenv", "callers may set variables",
                    "Rules can pass environment variables to the target command. Worth pairing with "
                    + "a dynamically linked sudo-allowed binary.", "", 0));
        }

        List<String> hygiene = new ArrayList<>();
        if (containsToken(lower, "env_reset")) {
            hygiene.add("env_reset (scrubs the environment)");
        }
        if (lower.contains("secure_path")) {
            hygiene.add("secure_path (fixed PATH, blocks PATH hijacking)");
        }
        if (containsToken(lower, "use_pty")) {
            hygiene.add("use_pty (runs in a pty, limits some escapes)");
        }
        if (containsToken(lower, "requiretty")) {
            hygiene.add("requiretty (no sudo without a tty)");
        }
        if (!hygiene.isEmpty()) {
            out.add(Finding.of(Severity.OK, "Defaults (hardening)", "sensible defaults in place",
                    "Good hygiene present: " + String.join("; ", hygiene) + ". These are the "
                    + "settings that make the easy tricks not work.", "", 0));
        }
        return out;
    }

    /** Pulls leading TAG: and OPTION= tokens off the command portion, collecting the tag names. */
    private static String stripTags(String rest, Set<String> tags) {
        String remaining = rest.strip();
        while (true) {
            Matcher tag = TAG.matcher(remaining);
            Matcher option = OPTION.matcher(remaining);
            if (tag.matches()) {
                tags.add(tag.group(1));
                remaining = tag.group(2).strip();
            } else if (option.matches()) {
                tags.add(option.group(1));
                remaining = option.group(2).strip();
            } else {
                return remaining;
            }
        }
    }

    private static boolean mentionsRoot(String userPart) {
        String u = userPart.toLowerCase();
        for (String token : u.split("[,\\s]+")) {
            String t = token.strip();
            if (t.equals("all") || t.equals("root") || t.equals("#0")) {
                return true;
            }
        }
        return u.isBlank();   // an empty runas defaults to root
    }

    private static String firstUser(String runasLabel) {
        String user = runasLabel.contains(":") ? runasLabel.substring(0, runasLabel.indexOf(':')) : runasLabel;
        for (String token : user.split("[,\\s]+")) {
            String t = token.strip();
            if (!t.isEmpty() && !t.startsWith("!")) {
                return t.equalsIgnoreCase("all") ? "root" : t;
            }
        }
        return "root";
    }

    private static boolean containsToken(String haystack, String token) {
        return (" " + haystack + " ").contains(" " + token + " ")
                || (" " + haystack + ",").contains(" " + token + ",")
                || haystack.contains(token + "=");
    }

    private static String basename(String program) {
        String p = program.strip();
        int slash = p.lastIndexOf('/');
        return (slash >= 0 ? p.substring(slash + 1) : p).toLowerCase();
    }
}
