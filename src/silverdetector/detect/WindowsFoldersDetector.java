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
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;
import silverdetector.core.Table;

/**
 * WORKED EXAMPLE - NOT SWITCHED ON.
 *
 * <p>This is the "I found a new use, like Windows default folders" detector from
 * {@code docs/ADDING_DETECTORS.md}, written out in full so there is something real to copy.
 * It reads a directory listing from a Windows host and says which folders are stock and which
 * are not.
 *
 * <p>To switch it on, add one line to {@code silverdetector.core.DetectorRegistry#all()}:
 * <pre>
 *     new WindowsFoldersDetector(),
 * </pre>
 * then {@code ./build.sh}. Its knowledge lives in {@code data/windows_paths.tsv}, so most of
 * what you will ever want to change is a .tsv row, not code.
 */
public final class WindowsFoldersDetector implements Detector {

    // "  08/18/2026  10:22 AM    <DIR>          Program Files"     cmd.exe dir
    private static final Pattern CMD_DIR = Pattern.compile("^.*<DIR>\\s+(.+?)\\s*$");
    // "d-----         8/18/2026  10:22 AM                Program Files"   PowerShell
    private static final Pattern PS_DIR = Pattern.compile("^d[-ahrsl]{5}\\s+\\S+\\s+\\S+\\s*(?:AM|PM)?\\s+(?:\\d+\\s+)?(.+?)\\s*$");
    // "C:\Program Files" or "C:\Users\bob\AppData"
    private static final Pattern WIN_PATH = Pattern.compile("^([A-Za-z]:\\\\[^\\s].*?)\\s*$");

    @Override
    public String id() {
        return "winfolders";
    }

    @Override
    public String name() {
        return "Windows folders";
    }

    @Override
    public String accepts() {
        return "dir / Get-ChildItem output, or a list of C:\\ paths";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public Detection sniff(Document doc) {
        List<String> names = names(doc);
        if (names.isEmpty()) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        int confidence = Math.min(95, 40 + (100 * names.size() / lines) * 55 / 100);
        return Detection.of(confidence, "Windows directory listing, %d entr%s",
                names.size(), names.size() == 1 ? "y" : "ies");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table known = Kb.table("windows_paths");
        List<Finding> findings = new ArrayList<>();

        for (Document.Line line : doc.contentLines()) {
            String name = nameOf(line.text());
            if (name == null) {
                continue;
            }
            Row row = known.first(normalise(name));
            Finding finding;
            if (row != null) {
                finding = Finding.of(Severity.parse(row.get("severity"), Severity.OK),
                        name, row.get("purpose", "standard folder"),
                        row.get("description", "Part of a stock Windows install."),
                        line.text().strip(), line.number())
                        .note("in the standard layout for " + row.get("since", "Windows"));
            } else {
                finding = Finding.of(Severity.NOTICE, name, "not a stock folder",
                        "No row in windows_paths.tsv. That is normal for installed software and "
                        + "for anything a user created - but staging directories for exfiltration "
                        + "look exactly like this too, so confirm what put it there.",
                        line.text().strip(), line.number());
            }
            findings.add(finding);
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private List<String> names(Document doc) {
        List<String> out = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String name = nameOf(line.text());
            if (name != null) {
                out.add(name);
            }
        }
        return out;
    }

    /** Pulls the folder name out of whichever listing format the line is in. */
    private static String nameOf(String text) {
        String line = text.strip();
        if (line.isEmpty() || line.startsWith("Directory of") || line.startsWith("Mode ")
                || line.startsWith("----") || line.endsWith("bytes free")) {
            return null;
        }
        Matcher cmd = CMD_DIR.matcher(line);
        if (cmd.matches()) {
            return skipDots(cmd.group(1));
        }
        Matcher ps = PS_DIR.matcher(line);
        if (ps.matches()) {
            return skipDots(ps.group(1));
        }
        Matcher path = WIN_PATH.matcher(line);
        if (path.matches()) {
            return skipDots(path.group(1));
        }
        return null;
    }

    private static String skipDots(String name) {
        String n = name.strip();
        return n.equals(".") || n.equals("..") ? null : n;
    }

    /** Table keys are lowercase leaf names, so "C:\Windows" and "Windows" both hit. */
    private static String normalise(String name) {
        String n = name.replace('/', '\\');
        while (n.endsWith("\\")) {
            n = n.substring(0, n.length() - 1);
        }
        int slash = n.lastIndexOf('\\');
        return (slash >= 0 ? n.substring(slash + 1) : n).toLowerCase();
    }
}
