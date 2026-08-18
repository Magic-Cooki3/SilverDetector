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
import silverdetector.core.Severity;

/**
 * Scheduled jobs: {@code crontab -l}, {@code /etc/crontab}, {@code /etc/cron.d/*}.
 *
 * <p>Cron is a favourite privesc route because a job often runs as root while pointing at a
 * script, a relative command, or a wildcard that a lower-privileged user can influence. The
 * detector looks for exactly those:
 * <ul>
 *   <li>a job whose script lives somewhere writable (see {@code writable_dirs.tsv})</li>
 *   <li>a relative command name, hijackable through {@code PATH}</li>
 *   <li>a {@code PATH=} line that puts a writable directory first</li>
 *   <li>archive tools with a {@code *} wildcard (checkpoint / argument injection)</li>
 * </ul>
 */
public final class CronDetector implements Detector {

    // min hour dom mon dow  -> each field is cron punctuation/numbers/short names
    private static final String FIELD = "[-0-9*/,A-Za-z]+";
    private static final Pattern TIMED = Pattern.compile(
            "^(" + FIELD + ")\\s+(" + FIELD + ")\\s+(" + FIELD + ")\\s+(" + FIELD + ")\\s+("
                    + FIELD + ")\\s+(.+)$");
    private static final Pattern NICKNAME = Pattern.compile(
            "^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)\\s+(.+)$");
    private static final Pattern ASSIGN = Pattern.compile("^([A-Z_][A-Z0-9_]*)=(.*)$");
    private static final Pattern USERNAME = Pattern.compile("^[a-z_][a-z0-9_-]{0,31}$");

    private static final List<String> WILDCARD_TOOLS = List.of(
            "tar", "rsync", "7z", "7za", "zip", "chown", "chmod");

    @Override
    public String id() {
        return "cron";
    }

    @Override
    public String name() {
        return "Scheduled jobs (cron)";
    }

    @Override
    public String accepts() {
        return "crontab -l, /etc/crontab, /etc/cron.d/* (5-field schedules or @reboot/@daily)";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public Detection sniff(Document doc) {
        int jobs = 0;
        int assigns = 0;
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            if (looksTimed(text) || NICKNAME.matcher(text).matches()) {
                jobs++;
            } else if (ASSIGN.matcher(text).matches()) {
                assigns++;
            }
        }
        if (jobs == 0) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        int confidence = Math.min(96, 45 + (100 * jobs / lines) / 2 + Math.min(15, jobs * 5)
                + (assigns > 0 ? 8 : 0));
        return Detection.of(confidence, "cron schedule, %d job%s", jobs, jobs == 1 ? "" : "s");
    }

    private static final java.util.Set<String> MONTHS = java.util.Set.of(
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec");
    private static final java.util.Set<String> DAYS = java.util.Set.of(
            "sun", "mon", "tue", "wed", "thu", "fri", "sat");

    private static boolean looksTimed(String text) {
        Matcher m = TIMED.matcher(text);
        return m.matches() && validSchedule(m);
    }

    /**
     * The five leading fields must be a real crontab schedule, not just five space-separated
     * tokens - otherwise a "find -ls" line ({@code 2101 32 -rwxr-sr-x 1 root ...}) reads as a
     * job. Minute 0-59, hour 0-23, day-of-month 1-31 (digits only), then month and weekday,
     * which may use names.
     */
    private static boolean validSchedule(Matcher m) {
        return numericField(m.group(1), 59)      // minute
                && numericField(m.group(2), 23)  // hour
                && numericField(m.group(3), 31)  // day of month - never a name
                && namedField(m.group(4), 12, MONTHS)
                && namedField(m.group(5), 7, DAYS);
    }

    /** A cron field of digits and punctuation only, every number within [0, max]. */
    private static boolean numericField(String value, int max) {
        if (!value.matches("[-0-9*/,]+")) {
            return false;
        }
        Matcher n = Pattern.compile("\\d+").matcher(value);
        while (n.find()) {
            try {
                if (Integer.parseInt(n.group()) > max) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /** Like {@link #numericField} but months/weekdays may also be three-letter names. */
    private static boolean namedField(String value, int max, java.util.Set<String> names) {
        if (value.matches("[-0-9*/,]+")) {
            return numericField(value, max);
        }
        for (String part : value.toLowerCase().split("[,/*-]")) {
            if (part.isEmpty()) {
                continue;
            }
            if (part.matches("\\d+")) {
                if (Integer.parseInt(part) > max) {
                    return false;
                }
            } else if (part.length() < 3 || !names.contains(part.substring(0, 3))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Finding> findings = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();

            Matcher assign = ASSIGN.matcher(text);
            if (assign.matches() && !looksTimed(text)) {
                Finding f = assessAssignment(assign.group(1), assign.group(2), text, line.number());
                if (f != null) {
                    findings.add(f);
                }
                continue;
            }

            String schedule;
            String remainder;
            Matcher timed = TIMED.matcher(text);
            Matcher nick = NICKNAME.matcher(text);
            if (timed.matches() && validSchedule(timed)) {
                schedule = text.substring(0, text.length() - timed.group(6).length()).strip();
                remainder = timed.group(6).strip();
            } else if (nick.matches()) {
                schedule = "@" + nick.group(1);
                remainder = nick.group(2).strip();
            } else {
                continue;
            }
            findings.add(assessJob(schedule, remainder, text, line.number()));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingInt(Finding::line));
        return findings;
    }

    private Finding assessJob(String schedule, String remainder, String evidence, int line) {
        // System crontabs (/etc/crontab, /etc/cron.d) insert a user field before the command.
        String runAs = null;
        String command = remainder;
        String[] tokens = remainder.split("\\s+", 2);
        if (tokens.length == 2 && USERNAME.matcher(tokens[0]).matches() && !tokens[0].contains("/")
                && !isCommandName(tokens[0])) {
            runAs = tokens[0];
            command = tokens[1].strip();
        }
        boolean root = "root".equals(runAs) || runAs == null;  // user crontabs run as their owner

        String program = firstWord(command);
        String scriptPath = program.startsWith("/") ? program : null;
        String writable = scriptPath != null ? WritableDirs.match(scriptPath) : null;

        Severity severity = Severity.OK;
        String label = "scheduled job";
        String detail = "A cron job. Nothing structurally wrong on its face - the risk is in what "
                + "the command points at.";
        List<String> notes = new ArrayList<>();

        if (writable != null) {
            severity = root ? Severity.CRITICAL : Severity.WARN;
            label = "cron runs a script from a writable location";
            detail = "The job runs " + scriptPath + ", which is under " + writable + " where a "
                    + "lower-privileged user can write. Overwrite that file and its contents run "
                    + (root ? "as root" : "as " + runAs) + " on the next tick.";
            notes.add("next: check write access with 'ls -l " + scriptPath + "' and the directory "
                    + "above it, then replace the script body");
        } else if (isSystemRunParts(command)) {
            severity = Severity.OK;
            label = "standard cron.d/run-parts job";
            detail = "Runs the scripts in a system cron directory (cron.hourly/daily/...). Expected; "
                    + "the scripts themselves are what to audit.";
        } else if (scriptPath == null && isHijackableName(program)) {
            severity = root ? Severity.NOTICE : Severity.INFO;
            label = "cron runs a relative command";
            detail = "The command '" + program + "' has no absolute path, so it is resolved through "
                    + "cron's PATH. If any earlier PATH directory is writable, you control what runs "
                    + (root ? "as root" : "as " + runAs) + ".";
            notes.add("next: note the PATH= line above and check each directory for write access");
        }

        String base = firstWord(command);
        for (String tool : WILDCARD_TOOLS) {
            if (base.equals(tool) || base.endsWith("/" + tool)) {
                if (command.contains("*")) {
                    severity = severity.max(root ? Severity.WARN : Severity.NOTICE);
                    notes.add(tool + " with a '*' wildcard: cron expands it in the job's working "
                            + "directory, so a file named like an option (e.g. --checkpoint-action) "
                            + "becomes argument injection - a classic wildcard privesc");
                }
                break;
            }
        }

        Finding finding = Finding.of(severity, "cron: " + shorten(command), label, detail, evidence, line);
        finding = finding.note("schedule: " + schedule + (runAs != null ? "   runs as: " + runAs
                : "   runs as: the crontab's owner"));
        for (String note : notes) {
            finding = finding.note(note);
        }
        return finding;
    }

    private Finding assessAssignment(String key, String value, String evidence, int line) {
        if (key.equals("PATH")) {
            List<String> writableEntries = new ArrayList<>();
            boolean relative = false;
            for (String dir : value.split(":")) {
                String d = dir.strip();
                if (d.isEmpty() || d.equals(".")) {
                    relative = true;
                    continue;
                }
                if (!d.startsWith("/")) {
                    relative = true;
                    continue;
                }
                if (WritableDirs.match(d) != null) {
                    writableEntries.add(d);
                }
            }
            if (relative || !writableEntries.isEmpty()) {
                String problem = relative ? "a relative entry ('.' or a non-absolute path)"
                        : "a writable directory (" + String.join(", ", writableEntries) + ")";
                return Finding.of(Severity.WARN, "cron PATH", "cron PATH contains " + problem,
                        "Cron resolves relative commands through this PATH. Because it includes "
                        + problem + ", planting a binary there that shadows a real command name runs "
                        + "it with the job's privileges (often root).",
                        evidence, line).note("next: drop a binary named like a cron-invoked command "
                        + "into that directory, earlier in PATH");
            }
            return Finding.of(Severity.OK, "cron PATH", "cron PATH set",
                    "PATH for the cron jobs. All entries are absolute and non-writable - good.",
                    evidence, line);
        }
        if (key.equals("MAILTO") || key.equals("SHELL") || key.equals("HOME") || key.equals("CRON_TZ")
                || key.equals("MAILFROM") || key.equals("RANDOM_DELAY")) {
            return Finding.of(Severity.INFO, "cron " + key, key + " set for cron",
                    "Environment for the cron jobs (" + key + "=" + value.strip() + ").",
                    evidence, line);
        }
        return null;
    }

    private static boolean isCommandName(String token) {
        // Distinguish a user field from a bare command like "logrotate": if it is a known-ish
        // command word we would rather treat it as the command, not a username.
        return List.of("run-parts", "test", "cd", "logger", "logrotate", "find", "bash", "sh",
                "python", "python3", "perl").contains(token);
    }

    private static boolean isSystemRunParts(String command) {
        return command.contains("run-parts") || command.contains("/etc/cron.");
    }

    /** A bare command name worth flagging - not a shell builtin, which cannot be PATH-hijacked. */
    private static boolean isHijackableName(String program) {
        if (program.isEmpty() || program.startsWith("%") || program.startsWith("[")) {
            return false;
        }
        return !List.of("cd", "test", "echo", "true", "false", ":", ".", "source", "exec",
                "set", "export", "umask").contains(program);
    }

    private static String firstWord(String command) {
        String c = command.strip();
        int space = c.indexOf(' ');
        return space < 0 ? c : c.substring(0, space);
    }

    private static String shorten(String command) {
        String c = command.strip();
        return c.length() <= 48 ? c : c.substring(0, 47) + "…";
    }
}
