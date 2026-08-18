package silverdetector;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import silverdetector.core.Analyzer;
import silverdetector.core.Ansi;
import silverdetector.core.Detector;
import silverdetector.core.DetectorRegistry;
import silverdetector.core.Document;
import silverdetector.core.Kb;
import silverdetector.core.Severity;
import silverdetector.report.JsonReport;
import silverdetector.report.TextReport;

/**
 * Command line entry point.
 *
 * <p>Exit codes, so it can be used in a script:
 * <pre>
 *   0  nothing above NOTICE (or above INFO with --strict)
 *   1  anomalies found
 *   2  usage or I/O error
 *   3  nothing recognised the input
 * </pre>
 */
public final class Main {

    public static final String VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) {
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(System.err, true, StandardCharsets.UTF_8);

        String file = null;
        String forcedId = null;
        boolean json = false;
        boolean showNormal = true;
        boolean strict = false;
        Boolean colour = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-h", "--help" -> {
                    usage(out);
                    System.exit(0);
                }
                case "-v", "--version" -> {
                    out.println("silverdetector " + VERSION);
                    System.exit(0);
                }
                case "-l", "--list" -> {
                    Ansi.enabled(colour == null ? Ansi.autoDetect() : colour);
                    list(out);
                    System.exit(0);
                }
                case "-d", "--detector" -> {
                    if (i + 1 >= args.length) {
                        err.println("--detector needs an id (see --list)");
                        System.exit(2);
                    }
                    forcedId = args[++i];
                }
                case "--update" -> {
                    err.println("--update is handled by the silverdetector/silverfinder launcher, "
                            + "not the jar directly.");
                    err.println("run:  silverfinder --update <github-zip-url | path/to.zip>");
                    System.exit(2);
                }
                case "--json" -> json = true;
                case "-q", "--anomalies", "--only-anomalies" -> showNormal = false;
                case "-a", "--all" -> showNormal = true;
                case "--strict" -> strict = true;
                case "--color", "--colour" -> colour = true;
                case "--no-color", "--no-colour" -> colour = false;
                case "-" -> file = null;
                default -> {
                    if (arg.startsWith("--detector=")) {
                        forcedId = arg.substring("--detector=".length());
                    } else if (arg.startsWith("-")) {
                        err.println("unknown option: " + arg);
                        usage(err);
                        System.exit(2);
                    } else if (file == null) {
                        file = arg;
                    } else {
                        err.println("only one input file at a time (got " + file + " and " + arg + ")");
                        System.exit(2);
                    }
                }
            }
        }

        Ansi.enabled(colour == null ? Ansi.autoDetect() : colour);
        if (json) {
            Ansi.enabled(false);
        }

        Detector forced = null;
        if (forcedId != null) {
            forced = DetectorRegistry.byId(forcedId);
            if (forced == null) {
                err.println("no such detector: " + forcedId);
                err.println("available: " + String.join(", ", DetectorRegistry.ids()));
                System.exit(2);
            }
        }

        Document doc;
        try {
            if (file == null) {
                doc = Document.fromStream("<stdin>", System.in);
            } else {
                Path path = Paths.get(file);
                if (!Files.exists(path)) {
                    err.println("no such file: " + path);
                    System.exit(2);
                }
                if (Files.isDirectory(path)) {
                    err.println("that is a directory: " + path);
                    System.exit(2);
                }
                doc = Document.fromFile(path);
            }
        } catch (IOException e) {
            err.println("could not read input: " + e.getMessage());
            System.exit(2);
            return;
        }

        Analyzer.Result result = Analyzer.run(doc, DetectorRegistry.all(), forced);

        if (json) {
            new JsonReport(out).print(result);
        } else {
            new TextReport(out, showNormal).print(result);
        }

        if (!result.recognised()) {
            System.exit(3);
        }
        Severity worst = result.worst();
        Severity threshold = strict ? Severity.NOTICE : Severity.WARN;
        System.exit(worst.atLeast(threshold) ? 1 : 0);
    }

    private static void usage(PrintStream out) {
        out.println("""
                silverdetector - paste command output, get told what is normal and what is not

                USAGE
                  silverdetector [options] [file]
                  ... | silverdetector [options]          read the paste from stdin
                  silverdetector                          with no file, also reads stdin

                OPTIONS
                  -d, --detector <id>   skip auto-detection and use this reader (see --list)
                  -q, --anomalies       hide the normal entries, show only what stands out
                  -a, --all             show everything, normal entries included (default)
                      --json            machine-readable output
                      --strict          exit 1 on NOTICE too, not just WARN and CRIT
                      --color/--no-color
                  -l, --list            list detectors, knowledge-base tables and search path
                      --update <src>    update the whole tool from a GitHub zip URL or a .zip
                                        path, then rebuild (via the launcher; keeps a backup)
                  -h, --help            this text
                  -v, --version

                EXIT CODES
                  0 clean   1 anomalies found   2 usage/IO error   3 input not recognised

                EXAMPLES
                  ss -tulpn > /tmp/paste.txt && silverdetector /tmp/paste.txt
                  find / -perm -4000 -ls 2>/dev/null | silverdetector
                  silverdetector --json --anomalies scan.txt | jq '.runs[].findings[]'""");
    }

    private static void list(PrintStream out) {
        out.println();
        out.println(Ansi.bold("Detectors"));
        for (Detector detector : DetectorRegistry.all()) {
            out.printf("  %-9s %s%n", detector.id(), detector.name());
            out.println(Ansi.dim("            reads: " + detector.accepts()));
        }

        out.println();
        out.println(Ansi.bold("Knowledge base"));
        List<String> tables = List.of("ports", "listeners", "suid_known", "gtfobins",
                "capabilities", "caps_known", "hash_formats", "system_users", "groups",
                "writable_dirs", "service_cves", "kernel_cves", "http_headers",
                "windows_signatures", "windows_privileges", "windows_groups",
                "linux_signatures", "nmap_scripts", "sqlmap_steps", "sqlmap_dbms");
        for (String name : tables) {
            var table = Kb.table(name);
            out.printf("  %-17s %4d row%s  %s%n", name + ".tsv", table.size(),
                    table.size() == 1 ? " " : "s", Ansi.dim(String.join(" + ", shorten(table.sources()))));
        }

        out.println();
        out.println(Ansi.bold("Search path") + Ansi.dim("  (later directories override earlier ones)"));
        for (Path path : Kb.searchPathVerbose()) {
            out.println("  " + path);
        }
        String home = System.getProperty("user.home");
        out.println(Ansi.dim("  add your own rows in " + home + "/.config/silverdetector/data/<table>.tsv"));

        List<String> warnings = Kb.warnings();
        if (!warnings.isEmpty()) {
            out.println();
            out.println(Ansi.paint(Ansi.YELLOW, "Knowledge-base warnings"));
            warnings.forEach(w -> out.println("  " + w));
        }
        out.println();
    }

    private static List<String> shorten(List<String> sources) {
        List<String> out = new ArrayList<>();
        for (String source : sources) {
            int slash = source.lastIndexOf('/');
            out.add(slash >= 0 && source.length() > 40 ? "…" + source.substring(slash) : source);
        }
        return out;
    }
}
