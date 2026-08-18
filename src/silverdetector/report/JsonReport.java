package silverdetector.report;

import java.io.PrintStream;
import java.util.List;

import silverdetector.core.Analyzer;
import silverdetector.core.Finding;

/**
 * JSON output for piping into jq or a report generator. Hand-rolled so the tool stays
 * dependency-free: {@code javac} and nothing else.
 */
public final class JsonReport {

    private final PrintStream out;

    public JsonReport(PrintStream out) {
        this.out = out;
    }

    public void print(Analyzer.Result result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"source\": ").append(quote(result.document().source())).append(",\n");
        sb.append("  \"lines\": ").append(result.document().lineCount()).append(",\n");
        sb.append("  \"recognised\": ").append(result.recognised()).append(",\n");
        sb.append("  \"worst\": ").append(quote(result.worst().name())).append(",\n");

        sb.append("  \"candidates\": [\n");
        for (int i = 0; i < result.sniffs().size(); i++) {
            Analyzer.Run sniff = result.sniffs().get(i);
            sb.append("    {\"detector\": ").append(quote(sniff.detector().id()))
              .append(", \"confidence\": ").append(sniff.detection().confidence())
              .append(", \"summary\": ").append(quote(sniff.detection().summary()))
              .append("}").append(i < result.sniffs().size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");

        sb.append("  \"runs\": [\n");
        for (int i = 0; i < result.runs().size(); i++) {
            Analyzer.Run run = result.runs().get(i);
            sb.append("    {\n");
            sb.append("      \"detector\": ").append(quote(run.detector().id())).append(",\n");
            sb.append("      \"name\": ").append(quote(run.detector().name())).append(",\n");
            sb.append("      \"confidence\": ").append(run.detection().confidence()).append(",\n");
            sb.append("      \"summary\": ").append(quote(run.detection().summary())).append(",\n");
            sb.append("      \"guessed\": ").append(run.guessed()).append(",\n");
            sb.append("      \"findings\": [\n");
            List<Finding> findings = run.findings();
            for (int j = 0; j < findings.size(); j++) {
                sb.append(finding(findings.get(j)));
                sb.append(j < findings.size() - 1 ? ",\n" : "\n");
            }
            sb.append("      ]\n");
            sb.append("    }").append(i < result.runs().size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        out.println(sb);
    }

    private static String finding(Finding finding) {
        StringBuilder sb = new StringBuilder();
        sb.append("        {");
        sb.append("\"severity\": ").append(quote(finding.severity().name())).append(", ");
        sb.append("\"anomaly\": ").append(finding.isAnomaly()).append(", ");
        sb.append("\"subject\": ").append(quote(finding.subject())).append(", ");
        sb.append("\"label\": ").append(quote(finding.label())).append(", ");
        sb.append("\"detail\": ").append(quote(finding.detail())).append(", ");
        sb.append("\"notes\": [");
        List<String> notes = finding.notes();
        for (int i = 0; i < notes.size(); i++) {
            sb.append(quote(notes.get(i)));
            if (i < notes.size() - 1) {
                sb.append(", ");
            }
        }
        sb.append("], ");
        sb.append("\"line\": ").append(finding.line()).append(", ");
        sb.append("\"evidence\": ").append(quote(finding.evidence()));
        sb.append("}");
        return sb.toString();
    }

    private static String quote(String value) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
