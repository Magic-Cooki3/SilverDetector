package silverdetector.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Loads the .tsv knowledge base. This is the "add stuff without writing Java" half of the tool.
 *
 * <p>File format, deliberately forgiving:
 * <pre>
 *   # comment lines and blank lines are ignored
 *   port    proto   service   risk    description      &lt;- first non-comment line is the header
 *   22      tcp     ssh       normal  Secure Shell ...
 * </pre>
 * Columns are separated by tabs. If a line contains no tab at all, two-or-more spaces are
 * accepted instead, so a hand-typed line still parses.
 *
 * <p>Search path, later entries win per key:
 * <ol>
 *   <li>{@code /data/&lt;name&gt;.tsv} bundled in the jar</li>
 *   <li>{@code $SILVERDETECTOR_HOME/data}</li>
 *   <li>{@code data/} next to the jar (and one directory up, for a repo checkout)</li>
 *   <li>{@code ./data} in the current directory</li>
 *   <li>every directory in {@code $SILVERDETECTOR_DATA} (colon separated)</li>
 *   <li>{@code ~/.config/silverdetector/data} - your personal overrides</li>
 * </ol>
 */
public final class Kb {

    private static final Map<String, Table> CACHE = new HashMap<>();
    private static final List<String> WARNINGS = new ArrayList<>();

    private Kb() {
    }

    /** Loads (and caches) the table called {@code name}, i.e. {@code data/<name>.tsv}. */
    public static synchronized Table table(String name) {
        Table cached = CACHE.get(name);
        if (cached != null) {
            return cached;
        }
        Table table = load(name);
        CACHE.put(name, table);
        return table;
    }

    /** Warnings collected while parsing (malformed rows and so on). Shown by {@code --list}. */
    public static synchronized List<String> warnings() {
        return List.copyOf(WARNINGS);
    }

    private static Table load(String name) {
        String fileName = name + ".tsv";
        List<String> columns = null;
        List<Object[]> pending = new ArrayList<>(); // [source, List<Row-as-map>]

        // 1. bundled resource
        try (InputStream in = Kb.class.getResourceAsStream("/data/" + fileName)) {
            if (in != null) {
                Parsed parsed = parse(new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)),
                        "bundled:" + fileName);
                if (parsed != null) {
                    columns = parsed.columns;
                    pending.add(new Object[]{parsed.source, parsed.rows});
                }
            }
        } catch (IOException e) {
            WARNINGS.add("could not read bundled " + fileName + ": " + e.getMessage());
        }

        // 2..6 files on disk
        for (Path dir : searchPath()) {
            Path file = dir.resolve(fileName);
            if (!Files.isReadable(file)) {
                continue;
            }
            try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                Parsed parsed = parse(reader, file.toString());
                if (parsed == null) {
                    continue;
                }
                if (columns == null) {
                    columns = parsed.columns;
                } else if (!columns.equals(parsed.columns)) {
                    // Different header: keep the first one, but only if the new file is a subset.
                    for (String c : parsed.columns) {
                        if (!columns.contains(c)) {
                            WARNINGS.add(file + ": unknown column '" + c + "' (header of " + fileName
                                    + " is " + String.join(", ", columns) + ")");
                        }
                    }
                }
                pending.add(new Object[]{parsed.source, parsed.rows});
            } catch (IOException e) {
                WARNINGS.add("could not read " + file + ": " + e.getMessage());
            }
        }

        if (columns == null) {
            WARNINGS.add("no knowledge-base file found for '" + name + "' (looked for " + fileName + ")");
            return new Table(name, List.of());
        }

        Table table = new Table(name, columns);
        for (Object[] entry : pending) {
            String source = (String) entry[0];
            @SuppressWarnings("unchecked")
            List<Map<String, String>> raw = (List<Map<String, String>>) entry[1];
            List<Row> rows = new ArrayList<>(raw.size());
            for (Map<String, String> values : raw) {
                rows.add(new Row(values, source));
            }
            table.merge(source, rows);
        }
        return table;
    }

    private record Parsed(List<String> columns, List<Map<String, String>> rows, String source) {
    }

    private static Parsed parse(BufferedReader reader, String source) throws IOException {
        List<String> columns = null;
        List<Map<String, String>> rows = new ArrayList<>();
        String line;
        int lineNo = 0;
        while ((line = reader.readLine()) != null) {
            lineNo++;
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String[] cells = split(line);
            if (columns == null) {
                List<String> header = new ArrayList<>();
                for (String cell : cells) {
                    header.add(cell.strip().toLowerCase());
                }
                columns = header;
                continue;
            }
            if (cells.length > columns.size()) {
                WARNINGS.add(source + ":" + lineNo + ": " + cells.length + " fields but header has "
                        + columns.size() + " - extra fields ignored");
            }
            Map<String, String> values = new LinkedHashMap<>();
            for (int i = 0; i < columns.size(); i++) {
                values.put(columns.get(i), i < cells.length ? cells[i].strip() : "");
            }
            if (values.get(columns.get(0)).isEmpty()) {
                WARNINGS.add(source + ":" + lineNo + ": empty key column, row skipped");
                continue;
            }
            rows.add(values);
        }
        return columns == null ? null : new Parsed(columns, rows, source);
    }

    private static String[] split(String line) {
        String body = line.stripTrailing();
        if (body.indexOf('\t') >= 0) {
            return body.split("\t");
        }
        return body.strip().split(" {2,}");
    }

    /** Directories searched for .tsv files, in load order (later wins). */
    public static List<Path> searchPath() {
        LinkedHashSet<Path> dirs = new LinkedHashSet<>();

        String home = System.getenv("SILVERDETECTOR_HOME");
        if (home != null && !home.isBlank()) {
            dirs.add(Paths.get(home, "data"));
        }

        Path codeDir = codeSourceDir();
        if (codeDir != null) {
            dirs.add(codeDir.resolve("data"));
            Path parent = codeDir.getParent();
            if (parent != null) {
                dirs.add(parent.resolve("data"));
            }
        }

        dirs.add(Paths.get("data"));

        String extra = System.getenv("SILVERDETECTOR_DATA");
        if (extra != null && !extra.isBlank()) {
            for (String part : extra.split(java.io.File.pathSeparator)) {
                if (!part.isBlank()) {
                    dirs.add(Paths.get(part.trim()));
                }
            }
        }

        String userHome = System.getProperty("user.home");
        if (userHome != null) {
            String xdg = System.getenv("XDG_CONFIG_HOME");
            Path config = (xdg != null && !xdg.isBlank())
                    ? Paths.get(xdg, "silverdetector", "data")
                    : Paths.get(userHome, ".config", "silverdetector", "data");
            dirs.add(config);
        }

        // Resolve before de-duplicating: "data" and "/home/you/SilverDetector/data" are the
        // same directory when you run from the checkout, and loading it twice is just noise.
        LinkedHashSet<Path> real = new LinkedHashSet<>();
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try {
                real.add(dir.toRealPath());
            } catch (IOException e) {
                real.add(dir.toAbsolutePath().normalize());
            }
        }
        return new ArrayList<>(real);
    }

    /** Every directory we would look in, whether or not it exists - for {@code --list}. */
    public static List<Path> searchPathVerbose() {
        LinkedHashSet<Path> dirs = new LinkedHashSet<>(searchPath());
        return new ArrayList<>(dirs);
    }

    private static Path codeSourceDir() {
        try {
            URI uri = Kb.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path path = Paths.get(uri);
            return Files.isDirectory(path) ? path : path.getParent();
        } catch (Exception e) {
            return null;
        }
    }
}
