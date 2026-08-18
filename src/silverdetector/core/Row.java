package silverdetector.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** One line of a knowledge-base table, addressed by column name. */
public final class Row {

    private final Map<String, String> values;
    private final String origin;

    Row(Map<String, String> values, String origin) {
        this.values = new LinkedHashMap<>(values);
        this.origin = origin;
    }

    /** Column value, or "" when the column is missing or empty. Never null. */
    public String get(String column) {
        String v = values.get(column);
        return v == null ? "" : v;
    }

    public String get(String column, String fallback) {
        String v = get(column);
        return v.isEmpty() ? fallback : v;
    }

    public boolean has(String column) {
        return !get(column).isEmpty();
    }

    /** Case-insensitive equality test on a column. */
    public boolean is(String column, String expected) {
        return get(column).equalsIgnoreCase(expected);
    }

    /** Which file this row came from - handy when a user override surprises you. */
    public String origin() {
        return origin;
    }

    public Map<String, String> values() {
        return Map.copyOf(values);
    }

    @Override
    public String toString() {
        return values.toString();
    }
}
