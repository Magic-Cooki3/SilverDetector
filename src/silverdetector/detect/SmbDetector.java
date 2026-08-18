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
 * SMB / Samba enumeration: {@code smbclient -L}, {@code enum4linux}, {@code smbmap}, and the
 * nmap {@code smb-*} scripts.
 *
 * <p>Reports the things that turn "there is file sharing here" into an actual foothold: SMBv1 /
 * MS17-010, signing not required (relay), guest/null-session access, and the Samba version
 * (matched to CVEs automatically, e.g. SambaCry).
 */
public final class SmbDetector implements Detector {

    private static final Pattern SAMBA_VERSION = Pattern.compile(
            "(?i)\\bsamba\\b[^0-9]{0,10}(\\d+\\.\\d+(?:\\.\\d+)?)");
    private static final Pattern SHARE_ROW = Pattern.compile(
            "^\\s*(\\S.*?)\\s{2,}(Disk|IPC|Printer)\\b.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern VULN_SCRIPT = Pattern.compile("(?i)smb-vuln-([a-z0-9][a-z0-9-]*)");

    @Override
    public String id() {
        return "smb";
    }

    @Override
    public String name() {
        return "SMB / Samba shares";
    }

    @Override
    public String accepts() {
        return "smbclient -L, enum4linux, smbmap, nmap smb-* scripts";
    }

    @Override
    public int order() {
        return 22;
    }

    @Override
    public Detection sniff(Document doc) {
        int signals = 0;
        for (Document.Line line : doc.contentLines()) {
            if (isSmbSignal(line.text())) {
                signals++;
            }
        }
        if (signals == 0) {
            return Detection.NONE;
        }
        return Detection.of(Math.min(94, 45 + signals * 12), "SMB enumeration output");
    }

    private static boolean isSmbSignal(String text) {
        String lower = text.toLowerCase();
        return lower.contains("sharename")
                || lower.contains("smb-vuln")
                || lower.contains("ms17-010")
                || lower.contains("message_signing")
                || lower.contains("server signing")
                || lower.contains("smbv1") || lower.contains("smb1")
                || lower.contains("samba smbd") || SAMBA_VERSION.matcher(text).find()
                || lower.contains("enum4linux")
                || lower.startsWith("domain=[") || lower.contains("os=[windows")
                || SHARE_ROW.matcher(text).matches();
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Finding> findings = new ArrayList<>();
        java.util.Set<String> reportedSamba = new java.util.HashSet<>();
        String pendingVulnScript = null;   // an nmap smb-vuln-* script id awaiting its State line
        boolean sawShares = false;

        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            String lower = text.toLowerCase();

            // nmap prints the script id ("smb-vuln-ms17-010:") on one line and "State:
            // VULNERABLE" a line or two later, so carry the script name forward to the verdict.
            Matcher scriptId = VULN_SCRIPT.matcher(text);
            if (scriptId.find()) {
                pendingVulnScript = scriptId.group(1).toLowerCase();
            }
            if (pendingVulnScript != null && isVulnerableState(lower)) {
                findings.add(vulnFinding(pendingVulnScript, text, line.number()));
                pendingVulnScript = null;
                continue;
            }

            Matcher samba = SAMBA_VERSION.matcher(text);
            if (samba.find() && reportedSamba.add(samba.group(1))) {
                findings.add(assessSamba(samba.group(1), text, line.number()));
            }

            if (mentionsSmbv1(lower)) {
                findings.add(Finding.of(Severity.WARN, "smb/smbv1", "SMBv1 in use",
                        "SMBv1 is enabled. It is obsolete, unauthenticated in places, and the "
                        + "transport for MS17-010/EternalBlue. Confirm MS17-010 status.",
                        text, line.number()).note("next: nmap --script smb-vuln-ms17-010 -p445 <host>"));
            }

            if (signingDisabled(lower)) {
                findings.add(Finding.of(Severity.WARN, "smb/signing", "SMB signing not required",
                        "Message signing is disabled or not required, so SMB relay works: capture "
                        + "authentication (Responder) and relay it to this or another host (ntlmrelayx).",
                        text, line.number()).note("next: ntlmrelayx.py -tf targets.txt with Responder"));
            }

            if (guestOrNull(lower)) {
                boolean write = lower.contains("read/write") || lower.contains("read, write")
                        || lower.contains("writable");
                findings.add(Finding.of(write ? Severity.CRITICAL : Severity.WARN, "smb/anonymous",
                        write ? "guest/anonymous SMB access with write" : "guest/anonymous SMB access",
                        write ? "Anonymous or guest access with write - drop a payload in a share a "
                              + "privileged process or user will open."
                              : "Anonymous or guest access is allowed - enumerate users, shares and "
                              + "policies with no credentials.",
                        text, line.number()).note("next: smbclient -N -L //<host>/  and enum4linux -a <host>"));
            }

            Matcher share = SHARE_ROW.matcher(line.text());
            if (share.matches()) {
                sawShares = true;
                findings.add(assessShare(share.group(1).strip(), text, line.number()));
            }
        }

        if (sawShares && findings.stream().noneMatch(Finding::isAnomaly)) {
            findings.add(Finding.of(Severity.INFO, "smb", "SMB shares listed",
                    "Shares enumerated. Map each one (smbmap -H <host>) and check read/write access "
                    + "with your credentials or as guest.", "", 0));
        }
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingInt(Finding::line));
        return findings;
    }

    private static boolean isVulnerableState(String lower) {
        return lower.contains("vulnerable") && !lower.contains("not vulnerable")
                && !lower.contains("likely not");
    }

    private Finding vulnFinding(String script, String evidence, int line) {
        if (script.contains("ms17-010")) {
            return Finding.of(Severity.CRITICAL, "smb/ms17-010", "MS17-010 (EternalBlue) VULNERABLE",
                    "The host reports vulnerable to MS17-010 (CVE-2017-0143) - remote code execution "
                    + "as SYSTEM over SMBv1, the EternalBlue/WannaCry bug.", evidence, line)
                    .note("next: Metasploit ms17_010_eternalblue, or a standalone PoC");
        }
        return Finding.of(Severity.CRITICAL, "smb/" + script, "SMB script reports VULNERABLE",
                "The nmap script smb-vuln-" + script + " reports this host VULNERABLE. Look up what "
                + script + " covers and confirm before exploiting.", evidence, line);
    }

    private Finding assessSamba(String version, String evidence, int line) {
        List<ServiceCves.Hit> hits = ServiceCves.match("samba", version);
        if (hits.isEmpty()) {
            return Finding.of(Severity.INFO, "smb/samba", "Samba " + version,
                    "No CVE in service_cves.tsv matches this Samba version. Still worth checking "
                    + "searchsploit and the Samba advisories.", evidence, line);
        }
        Finding finding = Finding.of(ServiceCves.worst(hits), "smb/samba",
                "Samba " + version + " - known vulnerable",
                "This Samba version matches " + hits.size() + " known CVE"
                + (hits.size() == 1 ? "" : "s") + ".", evidence, line);
        for (String note : ServiceCves.notes(hits)) {
            finding = finding.note(note);
        }
        return finding;
    }

    private Finding assessShare(String name, String evidence, int line) {
        String bare = name.trim();
        boolean admin = bare.equalsIgnoreCase("ADMIN$") || bare.equalsIgnoreCase("C$")
                || bare.equalsIgnoreCase("IPC$") || bare.endsWith("$");
        if (admin) {
            return Finding.of(Severity.INFO, "smb/" + bare, "administrative share",
                    "Default administrative/hidden share. Reachable only with privileged "
                    + "credentials; listed here for completeness.", evidence, line);
        }
        return Finding.of(Severity.NOTICE, "smb/" + bare, "non-default share: " + bare,
                "A custom share. Check your access to it (smbmap) and what it holds - config, "
                + "backups, home directories and web roots are the usual finds.", evidence, line)
                .note("next: smbclient //<host>/" + bare + " -N  (or with creds)");
    }

    private static boolean mentionsSmbv1(String lower) {
        if (lower.contains("disabled") || lower.contains("not supported") || lower.contains("no smb1")) {
            return false;   // a line reporting SMB1 is OFF is the opposite of a finding
        }
        return lower.contains("smbv1") || lower.contains("reconnecting with smb1")
                || lower.contains("smb1 for") || lower.contains("using smb1")
                || (lower.contains("dialect") && lower.contains("nt lm 0.12"))
                || lower.contains("smb 1.0");
    }

    private static boolean signingDisabled(String lower) {
        if (!lower.contains("signing")) {
            return false;
        }
        return lower.contains("disabled") || lower.contains("not required") || lower.contains("false");
    }

    private static boolean guestOrNull(String lower) {
        return lower.contains("null session")
                || lower.contains("guest access")
                || lower.contains("allow guest")
                || lower.contains("anonymous login")
                || (lower.contains("guest") && lower.contains("mapping"));
    }
}
