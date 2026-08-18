package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Severity;

/**
 * FTP banners and scan output: the server product and version (matched to CVEs automatically),
 * and whether anonymous access is allowed.
 *
 * <p>Complements the {@code ports} detector rather than replacing it - ports says "21 is
 * cleartext and reachable", this says "that banner is vsftpd 2.3.4, which is the backdoored
 * release (CVE-2011-2523)". Version CVEs come from {@code data/service_cves.tsv}.
 */
public final class FtpDetector implements Detector {

    // vsFTPd 2.3.4  |  ProFTPD 1.3.5  |  Pure-FTPd  |  wu-ftpd 2.6.0
    private static final Pattern PRODUCT = Pattern.compile(
            "(?i)\\b(vsftpd|proftpd|pure-ftpd|wu-ftpd|filezilla)\\b[^0-9]{0,12}(\\d+\\.\\d+(?:\\.\\d+)?)?");
    private static final Pattern FTP_CODE = Pattern.compile("^(220|230|331|530|550|500)\\b.*");

    @Override
    public String id() {
        return "ftp";
    }

    @Override
    public String name() {
        return "FTP service (banner / CVE match)";
    }

    @Override
    public String accepts() {
        return "FTP banners, nmap ftp lines, or ftp-anon output";
    }

    @Override
    public int order() {
        return 24;
    }

    @Override
    public Detection sniff(Document doc) {
        int signals = 0;
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            if (PRODUCT.matcher(text).find() || anonSignal(text) || FTP_CODE.matcher(text).matches()) {
                signals++;
            }
        }
        if (signals == 0) {
            return Detection.NONE;
        }
        return Detection.of(Math.min(90, 45 + signals * 15), "FTP banner/scan output");
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Finding> findings = new ArrayList<>();
        boolean sawFtp = false;

        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();

            Matcher product = PRODUCT.matcher(text);
            if (product.find()) {
                sawFtp = true;
                String name = product.group(1).toLowerCase();
                String version = product.group(2);
                findings.add(assessProduct(name, version, text, line.number()));
            }

            if (anonSignal(text)) {
                sawFtp = true;
                findings.add(assessAnon(text, line.number()));
            }
        }

        if (sawFtp && findings.stream().noneMatch(Finding::isAnomaly)) {
            findings.add(Finding.of(Severity.INFO, "ftp", "FTP service seen",
                    "FTP is a cleartext protocol - credentials and file contents cross the network "
                    + "in the open. If you can get on the same segment, they are sniffable.", "", 0));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingInt(Finding::line));
        return findings;
    }

    private Finding assessProduct(String product, String version, String evidence, int line) {
        String shown = product + (version != null ? " " + version : "");
        if (version == null) {
            return Finding.of(Severity.INFO, "ftp/" + product, shown + " (no version)",
                    "FTP server identified but the banner gave no version. Grab it (nc host 21) "
                    + "to enable a CVE match.", evidence, line);
        }
        List<ServiceCves.Hit> hits = ServiceCves.match(product, version);
        if (hits.isEmpty()) {
            return Finding.of(Severity.INFO, "ftp/" + product, shown,
                    "No CVE in service_cves.tsv matches this version. That is not proof it is safe "
                    + "- check searchsploit and the vendor advisories for " + product + " "
                    + version + ".", evidence, line).note("cleartext protocol either way");
        }
        Finding finding = Finding.of(ServiceCves.worst(hits), "ftp/" + product,
                shown + " - known vulnerable", "This FTP server version matches "
                + hits.size() + " known CVE" + (hits.size() == 1 ? "" : "s") + ".",
                evidence, line);
        for (String note : ServiceCves.notes(hits)) {
            finding = finding.note(note);
        }
        return finding;
    }

    private Finding assessAnon(String text, int line) {
        boolean write = text.toLowerCase().contains("write") || text.toLowerCase().contains("read/write");
        Severity severity = write ? Severity.CRITICAL : Severity.WARN;
        String detail = write
                ? "Anonymous FTP with write access. Upload a web shell into a served directory, or "
                  + "drop a file somewhere a privileged process will read it."
                : "Anonymous FTP login is allowed. You can browse and download without credentials "
                  + "- look for config files, backups and source.";
        return Finding.of(severity, "ftp/anonymous", "anonymous FTP access allowed", detail,
                text, line).note("next: ftp <host>, log in as 'anonymous' with any password");
    }

    private static boolean anonSignal(String text) {
        String lower = text.toLowerCase();
        return lower.contains("anonymous ftp login allowed")
                || lower.contains("anonymous access allowed")
                || lower.contains("anonymous access: read")
                || lower.contains("ftp-anon:")
                || lower.contains("allow anonymous");
    }
}
