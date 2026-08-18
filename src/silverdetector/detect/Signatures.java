package silverdetector.detect;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;

/**
 * A regex-per-row "signature engine", shared by the Windows and Linux privesc detectors.
 *
 * <p>Both {@code winprivesc} and {@code linprivesc} do the same core job on a PEAS-style dump:
 * strip the terminal colours off each line, test it against a table of regexes, and turn every
 * hit into a finding that says what it is and where to take it. That shared machinery lives here
 * so the two detectors stay thin and a new check is always just a new row in a {@code .tsv}.
 */
final class Signatures {

    private static final Pattern ANSI = Pattern.compile("\u001b\\[[0-9;?]*[ -/]*[@-~]");

    /** One compiled signature row. */
    record Sig(String id, Pattern pattern, Severity severity, String category,
               String title, String meaning, String next) {
    }

    private Signatures() {
    }

    /** Removes ANSI colour codes (PEAS output is full of them) and trims. */
    static String clean(String text) {
        return ANSI.matcher(text).replaceAll("").strip();
    }

    /** Compiles a signature table once. A bad regex becomes a never-matching, self-describing row. */
    static List<Sig> load(String table) {
        List<Sig> out = new ArrayList<>();
        for (Row row : Kb.table(table).rows()) {
            String pattern = row.get("pattern");
            if (pattern.isEmpty()) {
                continue;
            }
            try {
                Pattern compiled = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                out.add(new Sig(row.get("id"), compiled,
                        Severity.parse(row.get("severity"), Severity.NOTICE),
                        row.get("category"), row.get("title", row.get("id")),
                        row.get("meaning"), row.get("next")));
            } catch (RuntimeException e) {
                out.add(new Sig(row.get("id"), Pattern.compile("(?!)"), Severity.NOTICE, "",
                        row.get("id"), "signature '" + row.get("id") + "' has an invalid regex: "
                        + e.getMessage(), ""));
            }
        }
        return out;
    }

    /** True if any signature matches this already-cleaned line - for cheap sniffing. */
    static boolean anyMatch(List<Sig> sigs, String cleanedLine) {
        for (Sig sig : sigs) {
            if (sig.pattern().matcher(cleanedLine).find()) {
                return true;
            }
        }
        return false;
    }

    /** Scans a whole document, emitting one finding per signature id that fires (deduped). */
    static List<Finding> scan(List<Sig> sigs, Document doc) {
        List<Finding> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Document.Line line : doc.contentLines()) {
            String text = clean(line.text());
            for (Sig sig : sigs) {
                if (sig.pattern().matcher(text).find() && seen.add(sig.id())) {
                    out.add(toFinding(sig, text, line.number()));
                }
            }
        }
        return out;
    }

    static Finding toFinding(Sig sig, String evidence, int line) {
        Finding finding = Finding.of(sig.severity(), sig.title(),
                sig.category().isEmpty() ? sig.title() : "[" + sig.category() + "] " + sig.title(),
                sig.meaning(), evidence, line);
        if (!sig.next().isEmpty()) {
            finding = finding.note("next: " + sig.next());
        }
        return finding;
    }
}
