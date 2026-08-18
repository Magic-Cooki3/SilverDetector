package silverdetector.detect;

import silverdetector.core.Kb;
import silverdetector.core.Row;

/**
 * Understands the crypt(5) password hashes that live in /etc/shadow (and, when someone has
 * misconfigured things, in /etc/passwd).
 *
 * <p>A hash looks like {@code $id$salt$digest}: the {@code id} names the algorithm, and that is
 * what decides how fast an attacker can crack it. The algorithm table lives in
 * {@code data/hash_formats.tsv} so the cracking notes (hashcat/john modes) stay editable.
 */
final class CryptHash {

    private CryptHash() {
    }

    /** True when a password field holds an actual hash rather than {@code x}, {@code *} or {@code !}. */
    static boolean isHash(String field) {
        String f = field == null ? "" : field.strip();
        if (f.startsWith("!") || f.startsWith("*")) {
            // Locked, but a hash may still sit behind the '!' (e.g. "!$6$..."). That is locked,
            // not crackable, so it is not treated as a live hash here.
            return false;
        }
        return f.startsWith("$") || isTraditionalDes(f);
    }

    /** Locked/disabled markers: {@code *}, {@code !}, {@code !!}, {@code !$6$...}, etc. */
    static boolean isLocked(String field) {
        String f = field == null ? "" : field.strip();
        return f.startsWith("!") || f.equals("*") || f.startsWith("*LK*");
    }

    /** The {@code id} between the first two {@code $}, lowercased; {@code des} for a bare DES hash. */
    static String algorithmId(String field) {
        String f = field == null ? "" : field.strip();
        if (f.startsWith("!")) {
            f = f.substring(1);               // peek behind a lock marker to name the algorithm
        }
        if (f.startsWith("$")) {
            int second = f.indexOf('$', 1);
            return second > 1 ? f.substring(1, second).toLowerCase() : "";
        }
        return isTraditionalDes(f) ? "des" : "";
    }

    /** Row from hash_formats.tsv for this field's algorithm, or null when unrecognised. */
    static Row describe(String field) {
        String id = algorithmId(field);
        return id.isEmpty() ? null : Kb.table("hash_formats").first(id);
    }

    /** A hint a learner can act on straight away: "crack with hashcat -m 1800 / john --format=sha512crypt". */
    static String crackHint(Row format) {
        if (format == null) {
            return "";
        }
        String hashcat = format.get("hashcat");
        String john = format.get("john");
        StringBuilder sb = new StringBuilder("crack offline with ");
        boolean haveHashcat = !hashcat.isEmpty() && !hashcat.equals("-");
        if (haveHashcat) {
            sb.append("hashcat -m ").append(hashcat);
        }
        if (!john.isEmpty() && !john.equals("-")) {
            sb.append(haveHashcat ? " or " : "").append("john --format=").append(john);
        }
        if (!haveHashcat && (john.isEmpty() || john.equals("-"))) {
            return "";
        }
        return sb.toString();
    }

    private static boolean isTraditionalDes(String f) {
        // 13-character DES crypt output over the crypt alphabet. Rare today, weak when present.
        return f.matches("[./0-9A-Za-z]{13}");
    }
}
