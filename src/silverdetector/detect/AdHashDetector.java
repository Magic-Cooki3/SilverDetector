package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;

/**
 * Active Directory / Windows credential material - the AD counterpart to {@link ShadowDetector}.
 *
 * <p>Where {@code shadow} turns a Unix crypt hash into a hashcat/john mode, this turns the hashes
 * an AD attack yields into a crack (or pass-the-hash, or relay) command:
 * <ul>
 *   <li><b>Kerberoast</b> {@code $krb5tgs$...} - service tickets, RC4 (hashcat 13100) and AES
 *       (19600/19700)</li>
 *   <li><b>AS-REP roast</b> {@code $krb5asrep$...} - RC4 (18200) and AES (19800/19900)</li>
 *   <li><b>NetNTLMv2 / v1</b> - Responder / relay captures (5600 / 5500)</li>
 *   <li><b>NT hashes</b> from an NTDS.dit / SAM dump ({@code user:rid:lm:nt:::}) - usually
 *       pass-the-hash, not cracked (1000)</li>
 *   <li><b>DCC2 / DCC</b> - cached domain logons, crack-only (2100 / 1100)</li>
 * </ul>
 *
 * <p>Each format is one row in {@code data/ad_hashes.tsv} - a regex plus the hashcat/john modes and
 * the "crack vs pass vs relay" guidance - so recognising one more format is a new row, not new
 * code. The detector builds the actual command line from the {@code hashcat} / {@code john}
 * columns, so "I captured a hash" becomes "here is exactly what to run".
 */
public final class AdHashDetector implements Detector {

    /** One compiled credential-format row from ad_hashes.tsv. */
    private record Fmt(String id, Pattern pattern, String name, Severity severity,
                       String hashcat, String john, String detail, String next) {
    }

    /** Running tally for one format across the paste. */
    private static final class Agg {
        final Fmt fmt;
        int count;
        String evidence;
        int line;
        boolean krbtgt;

        Agg(Fmt fmt) {
            this.fmt = fmt;
        }
    }

    @Override
    public String id() {
        return "adhash";
    }

    @Override
    public String name() {
        return "AD credential material (Kerberoast / AS-REP / NetNTLM / NTDS hashes)";
    }

    @Override
    public String accepts() {
        return "$krb5tgs$/$krb5asrep$ tickets, NetNTLMv1/v2 captures, NTDS/SAM NT hashes, DCC2";
    }

    @Override
    public int order() {
        return 6;
    }

    private static List<Fmt> load() {
        List<Fmt> out = new ArrayList<>();
        for (Row row : Kb.table("ad_hashes").rows()) {
            String pattern = row.get("pattern");
            if (pattern.isEmpty()) {
                continue;
            }
            try {
                out.add(new Fmt(row.get("id"), Pattern.compile(pattern, Pattern.CASE_INSENSITIVE),
                        row.get("name", row.get("id")),
                        Severity.parse(row.get("severity"), Severity.WARN),
                        row.get("hashcat"), row.get("john"), row.get("detail"), row.get("next")));
            } catch (RuntimeException e) {
                // A bad regex should never take the run down; just skip this format.
            }
        }
        return out;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Fmt> formats = load();
        int hits = 0;
        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            for (Fmt fmt : formats) {
                if (fmt.pattern().matcher(text).find()) {
                    hits++;
                    break;
                }
            }
        }
        if (hits == 0) {
            return Detection.NONE;
        }
        // These formats are structurally distinctive ($krb5tgs$, the NetNTLMv2 layout, the
        // aad3b435 empty-LM constant), so even one line is a confident match.
        int confidence = Math.min(97, 60 + hits * 10);
        return Detection.of(confidence, "captured AD credential hashes, %d line%s",
                hits, hits == 1 ? "" : "s");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Fmt> formats = load();
        Map<String, Agg> tally = new LinkedHashMap<>();

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            for (Fmt fmt : formats) {
                if (!fmt.pattern().matcher(text).find()) {
                    continue;
                }
                Agg agg = tally.computeIfAbsent(fmt.id(), k -> new Agg(fmt));
                agg.count++;
                if (agg.evidence == null) {
                    agg.evidence = text;
                    agg.line = line.number();
                }
                if (text.toLowerCase().contains("krbtgt")) {
                    agg.krbtgt = true;
                }
                break;   // one format per line - patterns are mutually exclusive
            }
        }

        List<Finding> findings = new ArrayList<>();
        if (tally.isEmpty()) {
            return findings;
        }

        int total = tally.values().stream().mapToInt(a -> a.count).sum();
        findings.add(Finding.of(Severity.NOTICE, "adhash", "captured AD credential material",
                "Hashes recovered from an AD attack. Below, each is turned into the exact cracking "
                + "mode - but read the guidance: NT hashes are usually passed, not cracked, and a "
                + "NetNTLM capture is better relayed live than cracked.", "", 0)
                .note(total + " hash" + (total == 1 ? "" : "es") + " across "
                        + tally.size() + " format" + (tally.size() == 1 ? "" : "s")));

        for (Agg agg : tally.values()) {
            findings.add(assess(agg));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assess(Agg agg) {
        Fmt fmt = agg.fmt;
        String label = agg.count + " hash" + (agg.count == 1 ? "" : "es") + " captured";
        Finding finding = Finding.of(fmt.severity(), fmt.name(), label, fmt.detail(),
                agg.evidence == null ? "" : agg.evidence, agg.line);

        String crack = crackCommand(fmt);
        if (!crack.isEmpty()) {
            finding = finding.note(crack);
        }
        if (!fmt.next().isEmpty()) {
            finding = finding.note("next: " + fmt.next());
        }
        if (agg.krbtgt) {
            finding = finding.atLeast(Severity.CRITICAL).note("this is the krbtgt account - its NT "
                    + "hash forges Golden Tickets for any user (ticketer.py / mimikatz kerberos::golden)");
        }
        return finding;
    }

    /** Builds "crack: hashcat -m <mode> hashes.txt rockyou.txt  (john: --format=<fmt>)". */
    private static String crackCommand(Fmt fmt) {
        String hc = fmt.hashcat();
        String john = fmt.john();
        boolean haveHc = !hc.isEmpty() && !hc.equals("-");
        boolean haveJohn = !john.isEmpty() && !john.equals("-");
        if (!haveHc && !haveJohn) {
            return "";
        }
        StringBuilder sb = new StringBuilder("crack: ");
        if (haveHc) {
            sb.append("hashcat -m ").append(hc)
                    .append(" hashes.txt /usr/share/wordlists/rockyou.txt");
        }
        if (haveJohn) {
            sb.append(haveHc ? "  (john: --format=" : "john --format=").append(john)
                    .append(haveHc ? ")" : " hashes.txt");
        }
        return sb.toString();
    }
}
