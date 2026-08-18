package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import silverdetector.core.Detection;
import silverdetector.core.Detector;
import silverdetector.core.Document;
import silverdetector.core.Finding;
import silverdetector.core.Kb;
import silverdetector.core.Row;
import silverdetector.core.Severity;
import silverdetector.core.Table;
import silverdetector.detect.Sockets.Exposure;
import silverdetector.detect.Sockets.Sock;

/**
 * Listening ports and socket tables: what is open, what it is called, what it does, and which
 * of them have no business being there.
 *
 * <p>Knowledge base: {@code data/ports.tsv} (port -> name, risk class, description) and
 * {@code data/listeners.tsv} (process names that are notable when they are the listener).
 * Unknown ports fall back to {@code /etc/services} for at least a name.
 */
public final class PortsDetector implements Detector {

    /** Linux default ephemeral range - a high loopback port in here is usually just a client. */
    private static final int EPHEMERAL_FLOOR = 32768;

    @Override
    public String id() {
        return "ports";
    }

    @Override
    public String name() {
        return "Listening ports / sockets";
    }

    @Override
    public String accepts() {
        return "ss -tulpn, netstat -tulpn, nmap (normal or -oG), lsof -i, or a bare list of ports";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Detection sniff(Document doc) {
        List<Sock> socks = Sockets.parse(doc);
        if (socks.isEmpty()) {
            return Detection.NONE;
        }
        int lines = Math.max(1, doc.contentLines().size());
        long matchedLines = socks.stream().map(Sock::line).distinct().count();
        int ratio = (int) (100L * matchedLines / lines);

        Map<String, Long> formats = new LinkedHashMap<>();
        for (Sock sock : socks) {
            formats.merge(sock.format(), 1L, Long::sum);
        }
        String dominant = formats.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("");

        int confidence;
        if (dominant.equals("bare")) {
            // A column of bare numbers is ambiguous, so score it below the structured formats.
            confidence = Math.min(65, 25 + ratio / 2);
        } else {
            confidence = Math.min(98, 55 + ratio * 4 / 10);
        }
        return Detection.of(confidence, "%s, %d port row%s",
                describeFormat(dominant), socks.size(), socks.size() == 1 ? "" : "s");
    }

    private static String describeFormat(String format) {
        return switch (format) {
            case "ss" -> "ss socket table";
            case "netstat" -> "netstat table";
            case "nmap" -> "nmap port table";
            case "nmap-grepable" -> "nmap grepable output";
            case "lsof" -> "lsof -i listing";
            case "bare" -> "plain list of port numbers";
            default -> "port listing";
        };
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table ports = Kb.table("ports");
        Table listeners = Kb.table("listeners");

        // One finding per port+protocol, even when it is bound on both v4 and v6.
        Map<String, List<Sock>> grouped = new LinkedHashMap<>();
        for (Sock sock : Sockets.parse(doc)) {
            if (!Sockets.isOpen(sock)) {
                continue;
            }
            grouped.computeIfAbsent(sock.proto() + "/" + sock.port(), k -> new ArrayList<>()).add(sock);
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, List<Sock>> entry : grouped.entrySet()) {
            findings.add(assess(entry.getValue(), ports, listeners));
        }

        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparingInt(f -> portOf(f.subject())));
        return findings;
    }

    private static int portOf(String subject) {
        int slash = subject.indexOf('/');
        try {
            return Integer.parseInt(slash >= 0 ? subject.substring(slash + 1) : subject);
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    private Finding assess(List<Sock> group, Table ports, Table listeners) {
        Sock first = group.get(0);
        String proto = first.proto();
        int port = first.port();
        String subject = proto + "/" + port;

        Exposure exposure = Exposure.LOOPBACK;
        Set<String> binds = new LinkedHashSet<>();
        Set<String> processes = new LinkedHashSet<>();
        Set<String> versions = new LinkedHashSet<>();
        for (Sock sock : group) {
            exposure = exposure.max(sock.exposure());
            if (!sock.bind().isEmpty()) {
                binds.add(sock.bind());
            }
            if (!sock.process().isEmpty()) {
                processes.add(sock.process());
            }
            if (!sock.version().isEmpty()) {
                versions.add(sock.version());
            }
        }
        if (group.stream().allMatch(s -> s.exposure() == Exposure.UNKNOWN)) {
            exposure = Exposure.UNKNOWN;
        }

        Row row = ports.find(String.valueOf(port), "proto", proto, "any");
        String service;
        String detail;
        Severity severity;
        String reason;

        if (row != null) {
            service = row.get("service", "unnamed service");
            detail = row.get("description", "no description in ports.tsv");
            String risk = row.get("risk", "normal").toLowerCase();
            severity = severityFor(risk, exposure);
            reason = reasonFor(risk, exposure);
        } else {
            String iana = EtcServices.name(port, proto);
            service = iana.isEmpty() ? "unknown" : iana + " (per /etc/services)";
            detail = iana.isEmpty()
                    ? "Not in ports.tsv and not in /etc/services. Find out which process owns it "
                      + "(ss -tulpnp / lsof -i :" + port + ") before you call it normal."
                    : "Not in ports.tsv; /etc/services calls it '" + iana + "'. No risk assessment "
                      + "available - confirm the owning process.";
            severity = unknownSeverity(port, exposure);
            reason = severity == Severity.INFO
                    ? "high loopback port, consistent with an ordinary outbound/ephemeral socket"
                    : "no knowledge-base entry for this port";
        }

        Finding finding = Finding.of(severity, subject, service, detail,
                first.raw().strip(), first.line());

        if (!reason.isEmpty()) {
            finding = finding.note(reason);
        }
        if (!binds.isEmpty()) {
            finding = finding.note("bound on " + String.join(", ", binds) + " (" + exposure.description + ")");
        } else if (exposure == Exposure.REMOTE) {
            finding = finding.note("reported by a scan, so it answered over the network");
        }
        if (!processes.isEmpty()) {
            finding = finding.note("process: " + String.join(", ", processes));
        }
        if (!versions.isEmpty()) {
            finding = finding.note("banner: " + String.join(", ", versions));
        }
        if (group.size() > 1) {
            finding = finding.note(group.size() + " matching rows (lines "
                    + joinLines(group) + ")");
        }

        // The listener itself can be the anomaly: nc, socat, a bare python on a port.
        for (String process : processes) {
            Row hit = listeners.first(basename(process));
            if (hit == null) {
                continue;
            }
            Severity floor = Severity.parse(hit.get("severity"), Severity.WARN);
            String note = hit.get("description");
            if (floor.isAnomaly()) {
                finding = finding.atLeast(floor).note(process + ": " + note);
            } else {
                finding = finding.note(process + ": " + note);
            }
        }
        return finding;
    }

    private static String joinLines(List<Sock> group) {
        List<String> numbers = new ArrayList<>();
        for (Sock sock : group) {
            numbers.add(String.valueOf(sock.line()));
        }
        return String.join(", ", numbers);
    }

    private static String basename(String process) {
        String name = process.strip();
        int slash = name.lastIndexOf('/');
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        int colon = name.indexOf(':');
        if (colon > 0) {
            name = name.substring(0, colon);
        }
        return name.toLowerCase();
    }

    /**
     * risk classes in ports.tsv:
     * normal       - expected on a normal box, exposed or not
     * local        - fine on loopback, wrong when it answers off-box
     * local-strict - same, but unauthenticated by default, so exposure is critical
     * sensitive    - worth a look wherever it is
     * dangerous    - cleartext, legacy or routinely exploited
     * malware      - default port of a handler/backdoor/C2
     */
    private static Severity severityFor(String risk, Exposure exposure) {
        boolean exposed = exposure.reachableOffBox();
        return switch (risk) {
            case "malware" -> Severity.CRITICAL;
            case "dangerous" -> exposed ? Severity.CRITICAL : Severity.WARN;
            case "local-strict" -> exposed ? Severity.CRITICAL : Severity.OK;
            case "sensitive" -> exposed ? Severity.WARN : Severity.NOTICE;
            case "local" -> exposed ? Severity.WARN : Severity.OK;
            default -> Severity.OK;
        };
    }

    private static String reasonFor(String risk, Exposure exposure) {
        boolean exposed = exposure.reachableOffBox();
        return switch (risk) {
            case "malware" -> "this is a default port for remote-access tooling, not a stock service";
            case "dangerous" -> exposed
                    ? "high-risk service reachable off this host"
                    : "high-risk service, but only on loopback";
            case "local-strict" -> exposed
                    ? "this service has no authentication in its default configuration and it is "
                      + "reachable off this host - treat anything it holds as public"
                    : "expected, and correctly bound to loopback (it has no authentication by "
                      + "default, so keep it there)";
            case "sensitive" -> exposed
                    ? "sensitive service reachable off this host - it should normally be behind "
                      + "localhost, a VPN or a firewall"
                    : "sensitive service, correctly kept on loopback";
            case "local" -> exposed
                    ? "normally a localhost-only service - this one answers on the network"
                    : "expected, and correctly bound to loopback";
            default -> exposed ? "expected service" : "expected service, loopback only";
        };
    }

    private static Severity unknownSeverity(int port, Exposure exposure) {
        if (exposure.reachableOffBox()) {
            return Severity.WARN;
        }
        if (port >= EPHEMERAL_FLOOR) {
            return Severity.INFO;
        }
        return Severity.NOTICE;
    }
}
