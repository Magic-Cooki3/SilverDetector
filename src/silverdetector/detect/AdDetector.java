package silverdetector.detect;

import java.util.Comparator;
import java.util.List;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Severity;

/**
 * Active Directory enumeration and attack - the "paste an AD scan you don't fully understand and
 * be told what it is and where to take it" detector, the domain-network counterpart to the
 * winPEAS/linPEAS local-privesc engines.
 *
 * <p>It reads the output of the tools an AD assessment actually runs - NetExec / CrackMapExec,
 * enum4linux-ng, {@code ldapsearch}, BloodHound / SharpHound, PowerView, Impacket
 * (GetUserSPNs / GetNPUsers / secretsdump / ntlmrelayx), Rubeus, Certipy, Responder, kerbrute and
 * the coercion tools - and maps every interesting line to a technique, through the shared
 * {@link Signatures} engine and {@code data/ad_signatures.tsv}. Each finding says what the line
 * means and the {@code next:} command to run.
 *
 * <p>The categories mirror how an AD attack unfolds: enumeration, credentials/spraying, Kerberos
 * (kerberoast / AS-REP / delegation / tickets), ACL abuse (the BloodHound edges), AD CS
 * (ESC1-ESC13), coercion &amp; relay, the high-impact CVEs (Zerologon, noPac, PrintNightmare),
 * credential dumping, lateral movement and trusts.
 *
 * <p>All of that knowledge is TSV rows, so covering one more tool, edge, ESC or CVE is a new line
 * in {@code data/ad_signatures.tsv} - the code never changes. The captured hashes themselves
 * (kerberoast / AS-REP tickets, NetNTLM, NTDS/SAM NT hashes) are read by the sibling
 * {@link AdHashDetector}, which turns each into a hashcat/john command.
 */
public final class AdDetector implements Detector {

    /** Tool names whose mere presence marks a paste as AD tooling output (for sniffing). */
    private static final String[] TOOLS = {
        "netexec", "crackmapexec", "nxc ", "impacket", "bloodhound", "sharphound",
        "powerview", "sharpview", "ldapsearch", "windapsearch", "ldapdomaindump",
        "enum4linux", "rpcclient", "certipy", "certify", "kerbrute", "responder",
        "ntlmrelayx", "getuserspns", "getnpusers", "secretsdump", "rubeus", "evil-winrm",
        "mimikatz", "petitpotam", "zerologon", "nopac",
    };

    @Override
    public String id() {
        return "ad";
    }

    @Override
    public String name() {
        return "Active Directory enumeration / attack";
    }

    @Override
    public String accepts() {
        return "NetExec/CrackMapExec, enum4linux-ng, ldapsearch, BloodHound, Certipy, Impacket, "
                + "Rubeus, Responder or any AD tooling dump";
    }

    @Override
    public int order() {
        return 7;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Signatures.Sig> signatures = Signatures.load("ad_signatures");
        int sigHits = 0;
        boolean tool = false;

        for (Document.Line line : doc.contentLines()) {
            String text = Signatures.clean(line.text());
            if (!tool && namesAdTool(text.toLowerCase())) {
                tool = true;
            }
            if (Signatures.anyMatch(signatures, text)) {
                sigHits++;
            }
        }

        // Need a tool banner, or two independent signals: one lone generic match (a stray
        // "GenericAll" in prose) is not an AD scan, and claiming everything makes auto-detection
        // useless.
        if (!tool && sigHits < 2) {
            return Detection.NONE;
        }
        int confidence = (tool ? 60 : 20) + Math.min(45, sigHits * 12) + (sigHits > 0 ? 10 : 0);
        String summary = tool ? "AD tooling output" : "Active Directory enumeration";
        return Detection.of(Math.min(98, confidence),
                summary + ", " + sigHits + " signal" + (sigHits == 1 ? "" : "s"));
    }

    private static boolean namesAdTool(String lower) {
        for (String tool : TOOLS) {
            if (lower.contains(tool)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public List<Finding> analyze(Document doc) {
        List<Finding> findings = Signatures.scan(Signatures.load("ad_signatures"), doc);

        if (findings.isEmpty()) {
            findings.add(Finding.of(Severity.INFO, "ad", "AD output, nothing flagged",
                    "This looks like Active Directory tooling output, but no signature matched - "
                    + "either it is clean, or it holds something not yet in the knowledge base. Look "
                    + "for SPNs, delegation, LAPS and UAC flags by eye, and consider adding a "
                    + "signature row.", "", 0)
                    .note("signatures live in data/ad_signatures.tsv")
                    .note("captured hashes are read separately by the 'adhash' detector"));
        } else {
            findings.add(Finding.of(Severity.INFO, "ad", "Active Directory tooling recognised",
                    "Findings are grouped by attack stage - enumeration, credentials, Kerberos, "
                    + "delegation, ACLs, AD CS, coercion/relay, CVEs, dumping, lateral movement and "
                    + "trusts. Any kerberoast/AS-REP/NetNTLM/NTDS hashes in this paste are turned "
                    + "into crack commands by the 'adhash' detector.", "", 0)
                    .note("next steps assume you have a foothold; adjust host/user/domain to your target"));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }
}
