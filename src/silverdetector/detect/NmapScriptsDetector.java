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
 * Nmap NSE script results - the {@code | script-id:} blocks a scripted scan ({@code -sC},
 * {@code -A}, {@code --script}) prints under each port and under "Host script results".
 *
 * <p>The {@code ports} detector already reads the port/version table, and {@code smb}/{@code ftp}
 * pick up their services; this fills the gap the user asked about - "most if not all script
 * results". It explains the common scripts from {@code data/nmap_scripts.tsv}, and, crucially,
 * flags <em>any</em> {@code *-vuln-*} (or other) script that reports {@code VULNERABLE} even when
 * it is not in the table, so an unfamiliar script result still gets surfaced with a "look it up"
 * pointer rather than sliding past.
 */
public final class NmapScriptsDetector implements Detector {

    // The script id starts an NSE block: "| ssl-heartbleed:" / "|_ssl-poodle: ..." (lowercase,
    // usually hyphenated). Detail keys like "State:" or "Risk factor:" start with a capital.
    private static final Pattern SCRIPT_ID = Pattern.compile("^\\|_?\\s*([a-z][a-z0-9][a-z0-9_-]+):(.*)$");
    private static final Pattern PORT_LINE = Pattern.compile("^\\d{1,5}/(tcp|udp)\\b");

    @Override
    public String id() {
        return "nmapscripts";
    }

    @Override
    public String name() {
        return "Nmap NSE script results";
    }

    @Override
    public String accepts() {
        return "nmap -sC / -sV / -A / --script output (the | script blocks and Host script results)";
    }

    @Override
    public int order() {
        return 21;
    }

    @Override
    public Detection sniff(Document doc) {
        int scriptLines = 0;
        boolean nmap = false;
        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            String lower = text.toLowerCase();
            if (lower.startsWith("nmap scan report") || lower.startsWith("starting nmap")
                    || lower.startsWith("host script results") || lower.startsWith("nmap done")) {
                nmap = true;
            }
            if (SCRIPT_ID.matcher(text).matches() || text.startsWith("|")) {
                scriptLines++;
            }
        }
        if (scriptLines == 0) {
            return Detection.NONE;   // a plain port scan with no script output - ports handles it
        }
        int confidence = (nmap ? 55 : 30) + Math.min(40, scriptLines * 6);
        return Detection.of(Math.min(96, confidence),
                "nmap NSE script output, %d script line%s", scriptLines, scriptLines == 1 ? "" : "s");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table table = Kb.table("nmap_scripts");
        List<Finding> findings = new ArrayList<>();
        Set<String> emitted = new LinkedHashSet<>();
        String current = null;

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());

            if (PORT_LINE.matcher(text).find()) {
                current = null;   // a new port resets the script context
                continue;
            }

            Matcher sid = SCRIPT_ID.matcher(text);
            if (sid.matches()) {
                current = sid.group(1).toLowerCase();
                String rest = sid.group(2);
                Row row = table.first(current);
                if (row != null && row.is("kind", "info") && emitted.add(current)) {
                    findings.add(fromRow(current, row, text, line.number()));
                }
                if (isVulnerable(rest) || isVulnerable(text)) {
                    reportVuln(current, table, text, line.number(), emitted, findings);
                }
                continue;
            }

            // A detail line inside the current block ("|   State: VULNERABLE").
            if (current != null && isVulnerable(text)) {
                reportVuln(current, table, text, line.number(), emitted, findings);
            }
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private void reportVuln(String script, Table table, String evidence, int line,
                            Set<String> emitted, List<Finding> findings) {
        if (!emitted.add(script)) {
            return;   // already reported this script
        }
        Row row = table.first(script);
        if (row != null) {
            findings.add(fromRow(script, row, evidence, line));
        } else {
            findings.add(Finding.of(Severity.CRITICAL, "nse: " + script,
                    "nmap script reports VULNERABLE",
                    "The NSE script '" + script + "' reports this target VULNERABLE, and it is not "
                    + "in nmap_scripts.tsv. Look up what " + script + " checks and confirm before "
                    + "exploiting.", evidence, line)
                    .note("next: read the script's NSE docs / searchsploit the finding; add a row "
                            + "to nmap_scripts.tsv to explain it next time"));
        }
    }

    private Finding fromRow(String script, Row row, String evidence, int line) {
        Severity severity = Severity.parse(row.get("severity"), Severity.NOTICE);
        Finding finding = Finding.of(severity, "nse: " + script,
                row.get("title", script), row.get("meaning"), evidence, line);
        if (row.has("next")) {
            finding = finding.note("next: " + row.get("next"));
        }
        return finding;
    }

    private static boolean isVulnerable(String text) {
        String lower = text.toLowerCase();
        return lower.contains("vulnerable") && !lower.contains("not vulnerable")
                && !lower.contains("likely not") && !lower.contains("not likely");
    }
}
