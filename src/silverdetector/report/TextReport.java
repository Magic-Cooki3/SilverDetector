package silverdetector.report;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import silverdetector.core.Analyzer;
import silverdetector.core.Ansi;
import silverdetector.core.Detection;
import silverdetector.core.Finding;
import silverdetector.core.Severity;

/** The human-readable report. */
public final class TextReport {

    private final PrintStream out;
    private final boolean showNormal;

    public TextReport(PrintStream out, boolean showNormal) {
        this.out = out;
        this.showNormal = showNormal;
    }

    public void print(Analyzer.Result result) {
        out.println();
        out.println(Ansi.paint(Ansi.BOLD, "SilverDetector") + Ansi.dim("  ·  input: ")
                + result.document().source() + Ansi.dim(" (" + result.document().lineCount() + " lines)"));

        if (!result.recognised()) {
            printUnrecognised(result);
            return;
        }

        Map<Severity, Integer> totals = new EnumMap<>(Severity.class);
        // The report reads bottom-up: the summary sits at the foot by the prompt, so the worst
        // findings belong nearest it. Order the sections least-severe first, so the section
        // holding the top finding prints last. (Stable: ties keep detection order.)
        List<Analyzer.Run> ordered = new ArrayList<>(result.runs());
        ordered.sort(Comparator.comparingInt(TextReport::maxRank));
        for (Analyzer.Run run : ordered) {
            printRun(run, totals);
        }
        printSummary(result, totals);
    }

    private static int maxRank(Analyzer.Run run) {
        int max = 0;
        for (Finding finding : run.findings()) {
            max = Math.max(max, finding.severity().rank());
        }
        return max;
    }

    private void printRun(Analyzer.Run run, Map<Severity, Integer> totals) {
        Detection detection = run.detection();
        out.println();
        String header = Ansi.paint(Ansi.MAGENTA, "▸ " + run.detector().name());
        String recognised = detection.summary().isEmpty()
                ? "confidence " + detection.confidence() + "%"
                : detection.summary() + ", confidence " + detection.confidence() + "%";
        out.println(header + Ansi.dim("  [" + run.detector().id() + "]  " + recognised));
        if (run.guessed()) {
            out.println(Ansi.paint(Ansi.YELLOW, "  best guess only - if this is the wrong reader, "
                    + "force one with --detector <id>"));
        }
        out.println();

        List<Finding> shown = new ArrayList<>();
        int hidden = 0;
        for (Finding finding : run.findings()) {
            totals.merge(finding.severity(), 1, Integer::sum);
            if (!showNormal && !finding.isAnomaly()) {
                hidden++;
            } else {
                shown.add(finding);
            }
        }
        // Read bottom-up: lay the findings least-severe first so the worst is last, right above
        // the summary. A walkthrough (sqlmap) keeps its deliberate step order instead.
        if (!run.detector().sequential()) {
            shown.sort(Comparator.comparingInt(f -> f.severity().rank()));
        }
        // The hidden-count note is context, so it goes at the top of the section, out of the way
        // of the findings you are reading up towards.
        if (hidden > 0) {
            out.println(Ansi.dim("  (" + hidden + " normal entr" + (hidden == 1 ? "y" : "ies")
                    + " hidden - drop --anomalies to see them)"));
            out.println();
        }
        for (Finding finding : shown) {
            printFinding(finding);
        }
    }

    private void printFinding(Finding finding) {
        String badge = Ansi.paint(finding.severity().colour(),
                String.format("%-6s", finding.severity().label()));
        String subject = Ansi.bold(finding.subject());
        String label = finding.label().isEmpty() ? "" : Ansi.dim(" — ") + finding.label();
        out.println("  " + badge + " " + subject + label);

        if (!finding.detail().isEmpty()) {
            for (String line : wrap(finding.detail(), 88)) {
                out.println("         " + line);
            }
        }
        for (String note : finding.notes()) {
            for (String line : indentWrap(note, 84)) {
                out.println("         " + Ansi.dim(line));
            }
        }
        if (!finding.evidence().isEmpty()) {
            String where = finding.line() > 0 ? "line " + finding.line() + ": " : "";
            out.println("         " + Ansi.dim("└ " + where + truncate(finding.evidence(), 110)));
        }
        out.println();
    }

    private void printSummary(Analyzer.Result result, Map<Severity, Integer> totals) {
        int critical = totals.getOrDefault(Severity.CRITICAL, 0);
        int warn = totals.getOrDefault(Severity.WARN, 0);
        int notice = totals.getOrDefault(Severity.NOTICE, 0);
        int info = totals.getOrDefault(Severity.INFO, 0);
        int ok = totals.getOrDefault(Severity.OK, 0);
        int anomalies = critical + warn + notice;

        List<String> parts = new ArrayList<>();
        if (critical > 0) {
            parts.add(Ansi.paint(Severity.CRITICAL.colour(), critical + " critical"));
        }
        if (warn > 0) {
            parts.add(Ansi.paint(Severity.WARN.colour(), warn + " warning" + (warn == 1 ? "" : "s")));
        }
        if (notice > 0) {
            parts.add(Ansi.paint(Severity.NOTICE.colour(), notice + " notice" + (notice == 1 ? "" : "s")));
        }
        if (info > 0) {
            parts.add(Ansi.paint(Severity.INFO.colour(), info + " info"));
        }
        parts.add(Ansi.paint(Severity.OK.colour(), ok + " normal"));

        out.println(Ansi.dim("─".repeat(72)));
        String headline = anomalies == 0
                ? Ansi.paint(Severity.OK.colour(), "nothing abnormal found")
                : anomalies + " thing" + (anomalies == 1 ? "" : "s") + " to look at";
        out.println("  " + Ansi.bold(headline) + Ansi.dim("  ·  ") + String.join(Ansi.dim(" · "), parts));
        out.println(Ansi.dim("  read with: " + readers(result)));
        out.println();
    }

    private static String readers(Analyzer.Result result) {
        List<String> ids = new ArrayList<>();
        for (Analyzer.Run run : result.runs()) {
            ids.add(run.detector().id());
        }
        return String.join(", ", ids);
    }

    private void printUnrecognised(Analyzer.Result result) {
        out.println();
        if (result.document().isEmpty()) {
            out.println(Ansi.paint(Ansi.YELLOW, "  The input is empty - paste some command output into the file first."));
            out.println();
            return;
        }
        out.println(Ansi.paint(Ansi.YELLOW, "  Nothing recognised this input."));
        out.println();
        out.println("  Closest matches:");
        int shown = 0;
        for (Analyzer.Run sniff : result.sniffs()) {
            if (shown++ >= 4) {
                break;
            }
            out.printf("    %-10s %3d%%  %s%n", sniff.detector().id(),
                    sniff.detection().confidence(), sniff.detector().accepts());
        }
        out.println();
        out.println("  Force one with: --detector <id>     List everything with: --list");
        out.println();
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String word : text.split("\\s+")) {
            if (current.length() > 0 && current.length() + word.length() + 1 > width) {
                lines.add(current.toString());
                current.setLength(0);
            }
            if (current.length() > 0) {
                current.append(' ');
            }
            current.append(word);
        }
        if (current.length() > 0) {
            lines.add(current.toString());
        }
        return lines;
    }

    private static List<String> indentWrap(String note, int width) {
        List<String> wrapped = wrap(note, width);
        List<String> out = new ArrayList<>(wrapped.size());
        for (int i = 0; i < wrapped.size(); i++) {
            out.add((i == 0 ? "· " : "  ") + wrapped.get(i));
        }
        return out;
    }

    private static String truncate(String text, int max) {
        String single = text.replace("\t", " ").strip();
        return single.length() <= max ? single : single.substring(0, max - 1) + "…";
    }
}
