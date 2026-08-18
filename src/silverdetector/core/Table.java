package silverdetector.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A knowledge-base table loaded from one or more .tsv files.
 *
 * <p>Rows are indexed by the first column ("the key"). A key may hold several rows - port 53
 * has a tcp row and a udp row - so lookups return a list and the caller filters.
 */
public final class Table {

    private final String name;
    private final List<String> columns;
    private final Map<String, List<Row>> byKey = new LinkedHashMap<>();
    private final List<String> sources = new ArrayList<>();

    Table(String name, List<String> columns) {
        this.name = name;
        this.columns = List.copyOf(columns);
    }

    /**
     * Adds every row of one file. Any key defined in this file replaces all rows that earlier
     * files gave that key, which is what makes {@code ~/.config/silverdetector/data} an override
     * layer rather than a duplicate-generator.
     */
    void merge(String source, List<Row> rows) {
        sources.add(source);
        Map<String, List<Row>> incoming = new LinkedHashMap<>();
        for (Row row : rows) {
            String key = key(row);
            incoming.computeIfAbsent(key, k -> new ArrayList<>()).add(row);
        }
        byKey.putAll(incoming);
    }

    private String key(Row row) {
        return columns.isEmpty() ? "" : normalise(row.get(columns.get(0)));
    }

    private static String normalise(String key) {
        return key == null ? "" : key.trim().toLowerCase();
    }

    /** All rows filed under this key, in file order. Empty list when unknown. */
    public List<Row> get(String key) {
        return byKey.getOrDefault(normalise(key), List.of());
    }

    /** First row for this key, or null. */
    public Row first(String key) {
        List<Row> rows = get(key);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** First row for this key whose {@code column} matches one of {@code accepted}. */
    public Row find(String key, String column, String... accepted) {
        for (Row row : get(key)) {
            for (String want : accepted) {
                if (row.is(column, want)) {
                    return row;
                }
            }
        }
        return null;
    }

    public boolean containsKey(String key) {
        return byKey.containsKey(normalise(key));
    }

    public List<Row> rows() {
        List<Row> all = new ArrayList<>();
        byKey.values().forEach(all::addAll);
        return all;
    }

    public int size() {
        return rows().size();
    }

    public int keyCount() {
        return byKey.size();
    }

    public boolean isEmpty() {
        return byKey.isEmpty();
    }

    public String name() {
        return name;
    }

    public List<String> columns() {
        return columns;
    }

    /** The files that contributed to this table, in load order. */
    public List<String> sources() {
        return List.copyOf(sources);
    }
}
