package silverdetector.detect;

import java.util.ArrayList;
import java.util.List;

import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;

/**
 * "Does this product+version fall in a known-vulnerable range?" - the automatic-CVE lookup
 * shared by the FTP, SMB and HTTP detectors.
 *
 * <p>Knowledge lives in {@code data/service_cves.tsv}: one row per CVE, with a product name and
 * an inclusive {@code min}/{@code max} version range. Add a row and every detector that names
 * that product starts reporting it - no code change. An empty bound means "open ended".
 */
final class ServiceCves {

    /** One matched CVE for a given product+version. */
    record Hit(String cve, Severity severity, String description, String range) {
    }

    private ServiceCves() {
    }

    /** Every CVE whose range contains {@code version} for {@code product}. Empty when none. */
    static List<Hit> match(String product, String version) {
        List<Hit> hits = new ArrayList<>();
        if (product == null || product.isBlank()) {
            return hits;
        }
        Version v = Version.parse(version);
        if (!v.valid()) {
            return hits;
        }
        for (Row row : Kb.table("service_cves").get(product.trim().toLowerCase())) {
            String minStr = row.get("min");
            String maxStr = row.get("max");
            Version min = minStr.isEmpty() ? null : Version.parse(minStr);
            Version max = maxStr.isEmpty() ? null : Version.parse(maxStr);
            if (v.inRange(min, max)) {
                String range = (minStr.isEmpty() ? "*" : minStr) + " - " + (maxStr.isEmpty() ? "*" : maxStr);
                hits.add(new Hit(row.get("cve"), Severity.parse(row.get("severity"), Severity.WARN),
                        row.get("description"), range));
            }
        }
        return hits;
    }

    /** Turns hits into finding notes: "CVE-2021-41773 (CRIT): path traversal ...". */
    static List<String> notes(List<Hit> hits) {
        List<String> notes = new ArrayList<>();
        for (Hit hit : hits) {
            notes.add(hit.cve() + " [" + hit.severity().label() + ", affects " + hit.range() + "]: "
                    + hit.description());
        }
        return notes;
    }

    /** The worst severity among a set of hits, or OK when there are none. */
    static Severity worst(List<Hit> hits) {
        Severity worst = Severity.OK;
        for (Hit hit : hits) {
            worst = worst.max(hit.severity());
        }
        return worst;
    }
}
