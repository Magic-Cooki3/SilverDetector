package silverdetector.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import silverdetector.core.Document;

/**
 * Parses the many ways people dump a SUID/SGID hunt:
 *
 * <pre>
 *   find / -perm -4000 -type f 2&gt;/dev/null          -&gt; bare paths
 *   find / -perm -4000 -ls                            -&gt; inode, blocks, ls-style columns
 *   find / -perm -4000 -exec ls -la {} \;             -&gt; ls -l lines
 *   find / -perm /6000 -printf '%m %p\n'              -&gt; octal mode + path
 * </pre>
 */
final class PermEntries {

    /** A file (or directory) with its mode bits, as far as the paste reveals them. */
    record Entry(int line,
                 String raw,
                 String path,
                 String modeString,
                 String octal,
                 String owner,
                 String group,
                 boolean suid,
                 boolean sgid,
                 boolean sticky,
                 boolean directory,
                 boolean bitsKnown) {

        String basename() {
            int slash = path.lastIndexOf('/');
            return slash >= 0 ? path.substring(slash + 1) : path;
        }

        String directoryPart() {
            int slash = path.lastIndexOf('/');
            return slash > 0 ? path.substring(0, slash) : "/";
        }

        /** "SUID", "SGID", "SUID+SGID" or "" when the paste did not say. */
        String bitsLabel() {
            if (!bitsKnown) {
                return "";
            }
            if (suid && sgid) {
                return "SUID+SGID";
            }
            if (suid) {
                return "SUID";
            }
            if (sgid) {
                return "SGID";
            }
            return "no setid bits";
        }
    }

    private static final Pattern MODE = Pattern.compile("^([-dlcbpsD])([rwxsStT-]{9})[.+@]?$");
    private static final Pattern OCTAL_PATH = Pattern.compile("^([0-7]{3,5})\\s+(\\S+)$");
    private static final Pattern BARE_PATH = Pattern.compile("^(/\\S*)$");

    private PermEntries() {
    }

    static List<Entry> parse(Document doc) {
        List<Entry> entries = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            Entry entry = parseLine(line.number(), line.text());
            if (entry != null) {
                entries.add(entry);
            }
        }
        return entries;
    }

    private static Entry parseLine(int number, String raw) {
        String text = raw.strip();
        if (text.isEmpty()) {
            return null;
        }
        // find(1) noise that is not a result
        if (text.startsWith("find:") || text.contains("Permission denied")) {
            return null;
        }

        Entry listing = fromListing(number, raw, text);
        if (listing != null) {
            return listing;
        }

        Matcher octal = OCTAL_PATH.matcher(text);
        if (octal.matches()) {
            String path = cleanPath(octal.group(2));
            if (path.startsWith("/")) {
                return fromOctal(number, raw, path, octal.group(1), "", "");
            }
        }

        // A bare path is one token and nothing else. Anything after it means the line belongs
        // to some other format - getcap output ("/usr/bin/ping cap_net_raw=ep") in particular.
        Matcher bare = BARE_PATH.matcher(text);
        if (bare.matches()) {
            boolean looksLikeDir = bare.group(1).strip().endsWith("/");
            String path = cleanPath(bare.group(1));
            return new Entry(number, raw, path, "", "", "", "",
                    false, false, false, looksLikeDir, false);
        }
        return null;
    }

    /** ls -l / find -ls style: pull the mode token, then owner, group and the trailing path. */
    private static Entry fromListing(int number, String raw, String text) {
        String[] tokens = text.split("\\s+");
        int modeIndex = -1;
        Matcher modeMatcher = null;
        for (int i = 0; i < Math.min(tokens.length, 3); i++) {
            Matcher m = MODE.matcher(tokens[i]);
            if (m.matches()) {
                modeIndex = i;
                modeMatcher = m;
                break;
            }
        }
        if (modeIndex < 0) {
            return null;
        }
        String type = modeMatcher.group(1);
        String bits = modeMatcher.group(2);

        String owner = tokens.length > modeIndex + 2 ? tokens[modeIndex + 2] : "";
        String group = tokens.length > modeIndex + 3 ? tokens[modeIndex + 3] : "";

        String path = pathFromListing(text, tokens);
        if (path == null) {
            return null;
        }

        boolean suid = bits.charAt(2) == 's' || bits.charAt(2) == 'S';
        boolean sgid = bits.charAt(5) == 's' || bits.charAt(5) == 'S';
        boolean sticky = bits.charAt(8) == 't' || bits.charAt(8) == 'T';
        boolean directory = type.equals("d");
        return new Entry(number, raw, path, type + bits, octalOf(bits, suid, sgid, sticky),
                owner, group, suid, sgid, sticky, directory, true);
    }

    private static String pathFromListing(String text, String[] tokens) {
        int arrow = text.indexOf(" -> ");
        if (arrow > 0) {
            String left = text.substring(0, arrow).strip();
            String[] leftTokens = left.split("\\s+");
            String candidate = leftTokens[leftTokens.length - 1];
            return candidate.startsWith("/") ? cleanPath(candidate) : null;
        }
        // Walk backwards to the last token that looks like a path.
        for (int i = tokens.length - 1; i >= 0; i--) {
            if (tokens[i].startsWith("/")) {
                // Rejoin any trailing tokens: a path with spaces still ends the line.
                StringBuilder sb = new StringBuilder(tokens[i]);
                for (int j = i + 1; j < tokens.length; j++) {
                    sb.append(' ').append(tokens[j]);
                }
                return cleanPath(sb.toString());
            }
        }
        return null;
    }

    private static Entry fromOctal(int number, String raw, String path, String octal,
                                   String owner, String group) {
        String padded = octal.length() >= 4 ? octal : "0".repeat(4 - octal.length()) + octal;
        int special = padded.charAt(padded.length() - 4) - '0';
        boolean suid = (special & 4) != 0;
        boolean sgid = (special & 2) != 0;
        boolean sticky = (special & 1) != 0;
        return new Entry(number, raw, path, "", padded, owner, group,
                suid, sgid, sticky, path.endsWith("/"), true);
    }

    private static String octalOf(String bits, boolean suid, boolean sgid, boolean sticky) {
        int special = (suid ? 4 : 0) | (sgid ? 2 : 0) | (sticky ? 1 : 0);
        int user = value(bits.charAt(0), bits.charAt(1), bits.charAt(2));
        int grp = value(bits.charAt(3), bits.charAt(4), bits.charAt(5));
        int other = value(bits.charAt(6), bits.charAt(7), bits.charAt(8));
        return "" + special + user + grp + other;
    }

    private static int value(char r, char w, char x) {
        int v = 0;
        if (r == 'r') {
            v += 4;
        }
        if (w == 'w') {
            v += 2;
        }
        if (x == 'x' || x == 's' || x == 't') {
            v += 1;
        }
        return v;
    }

    private static String cleanPath(String path) {
        String p = path.strip();
        while (p.endsWith("*") || p.endsWith("|") || p.endsWith("=") || p.endsWith("@")) {
            p = p.substring(0, p.length() - 1);  // ls -F classifier characters
        }
        if (p.length() > 1 && p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        return p;
    }
}
