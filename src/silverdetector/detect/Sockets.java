package silverdetector.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import silverdetector.core.Document;

/**
 * Turns the many shapes of "here are my open ports" output into one record type.
 *
 * <p>Understood formats: {@code ss -tulpn}, {@code netstat -tulpn/-antp}, {@code nmap} normal
 * and grepable output, {@code lsof -i}, and a bare list of port numbers.
 */
final class Sockets {

    /** How reachable the port is - drives whether a service gets escalated. */
    enum Exposure {
        LOOPBACK("127.0.0.1 / ::1 only"),
        SPECIFIC("bound to one interface address"),
        WILDCARD("0.0.0.0 / :: - every interface"),
        REMOTE("seen from another host"),
        UNKNOWN("bind address not in the output");

        final String description;

        Exposure(String description) {
            this.description = description;
        }

        boolean reachableOffBox() {
            return this == WILDCARD || this == SPECIFIC || this == REMOTE;
        }

        Exposure max(Exposure other) {
            return ordinalWeight() >= other.ordinalWeight() ? this : other;
        }

        private int ordinalWeight() {
            return switch (this) {
                case LOOPBACK -> 0;
                case UNKNOWN -> 1;
                case SPECIFIC -> 2;
                case WILDCARD -> 3;
                case REMOTE -> 4;
            };
        }
    }

    /** One parsed socket row. */
    record Sock(int line,
                String raw,
                String proto,
                String bind,
                int port,
                String state,
                String process,
                String version,
                Exposure exposure,
                String format) {
    }

    // ss: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
    private static final Pattern SS = Pattern.compile(
            "^(tcp|udp|sctp|raw|dccp)6?\\s+([A-Z][A-Z0-9-]*)\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)(?:\\s+(.*))?$");

    // netstat: Proto Recv-Q Send-Q Local Foreign [State] [PID/Program]
    private static final Pattern NETSTAT = Pattern.compile(
            "^(tcp|udp|udplite|sctp|raw)6?\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)(?:\\s+([A-Z_]+))?(?:\\s+(\\S+))?\\s*$");

    // nmap normal output: 22/tcp open ssh OpenSSH 8.4p1
    private static final Pattern NMAP = Pattern.compile(
            "^(\\d{1,5})/(tcp|udp|sctp)\\s+(open\\|filtered|closed\\|filtered|open|closed|filtered|unfiltered)"
                    + "\\s+(\\S+)(?:\\s+(.*))?$");

    // lsof -i -P -n: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
    private static final Pattern LSOF = Pattern.compile(
            "^(\\S+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)\\s+(IPv4|IPv6)\\s+(\\S+)\\s+(\\S+)\\s+(TCP|UDP)\\s+(\\S+?)"
                    + "(?:\\s+\\(([A-Z]+)\\))?\\s*$");

    // nmap -oG: Ports: 22/open/tcp//ssh///, 80/open/tcp//http//nginx/
    private static final Pattern GREPABLE_ENTRY = Pattern.compile(
            "(\\d{1,5})/(open|closed|filtered)/(tcp|udp|sctp)/([^/]*)/([^/]*)/([^/]*)/([^/,]*)");

    // bare "22", "22/tcp", "tcp/22", "22,80,443"
    private static final Pattern BARE = Pattern.compile("^(?:(tcp|udp|sctp)/)?(\\d{1,5})(?:/(tcp|udp|sctp))?$");

    private Sockets() {
    }

    /** Parses every line it can. Lines it does not understand are silently skipped. */
    static List<Sock> parse(Document doc) {
        List<Sock> socks = new ArrayList<>();
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            if (text.isEmpty() || isHeader(text)) {
                continue;
            }
            List<Sock> parsed = parseLine(line.number(), line.text());
            socks.addAll(parsed);
        }
        return socks;
    }

    private static boolean isHeader(String text) {
        String lower = text.toLowerCase();
        return lower.startsWith("netid ")
                || lower.startsWith("proto ")
                || lower.startsWith("state ")
                || lower.startsWith("port ") && lower.contains("service")
                || lower.startsWith("command ") && lower.contains("pid")
                || lower.startsWith("active internet connections")
                || lower.startsWith("active unix domain")
                || lower.startsWith("starting nmap")
                || lower.startsWith("nmap scan report")
                || lower.startsWith("nmap done")
                || lower.startsWith("host is up")
                || lower.startsWith("not shown:")
                || lower.startsWith("mac address:")
                || lower.startsWith("service detection")
                || lower.startsWith("service info:");
    }

    private static List<Sock> parseLine(int number, String raw) {
        List<Sock> out = new ArrayList<>();
        String text = raw.strip();

        Sock sock = ss(number, raw, text);
        if (sock == null) {
            sock = nmap(number, raw, text);
        }
        if (sock == null) {
            sock = netstat(number, raw, text);
        }
        if (sock == null) {
            sock = lsof(number, raw, text);
        }
        if (sock != null) {
            out.add(sock);
            return out;
        }
        out.addAll(grepable(number, raw, text));
        if (out.isEmpty()) {
            out.addAll(bare(number, raw, text));
        }
        return out;
    }

    private static Sock ss(int number, String raw, String text) {
        Matcher m = SS.matcher(text);
        if (!m.matches()) {
            return null;
        }
        String proto = m.group(1);
        String state = m.group(2);
        String[] local = splitAddress(m.group(5));
        if (local == null) {
            return null;
        }
        String process = processFromSs(m.group(7));
        return new Sock(number, raw, proto, local[0], Integer.parseInt(local[1]),
                normaliseState(state), process, "", exposure(local[0]), "ss");
    }

    private static Sock netstat(int number, String raw, String text) {
        Matcher m = NETSTAT.matcher(text);
        if (!m.matches()) {
            return null;
        }
        String[] local = splitAddress(m.group(4));
        if (local == null) {
            return null;
        }
        String state = m.group(6) == null ? "" : m.group(6);
        String pidProg = m.group(7) == null ? "" : m.group(7);
        String process = pidProg.contains("/") ? pidProg.substring(pidProg.indexOf('/') + 1) : "";
        return new Sock(number, raw, m.group(1), local[0], Integer.parseInt(local[1]),
                normaliseState(state), process, "", exposure(local[0]), "netstat");
    }

    private static Sock nmap(int number, String raw, String text) {
        Matcher m = NMAP.matcher(text);
        if (!m.matches()) {
            return null;
        }
        int port = Integer.parseInt(m.group(1));
        if (port > 65535) {
            return null;
        }
        String version = m.group(5) == null ? "" : m.group(5).strip();
        return new Sock(number, raw, m.group(2), "", port, m.group(3), "",
                version, Exposure.REMOTE, "nmap");
    }

    private static Sock lsof(int number, String raw, String text) {
        Matcher m = LSOF.matcher(text);
        if (!m.matches()) {
            return null;
        }
        String name = m.group(9);
        // NAME is like *:22, 127.0.0.1:631 or 10.0.0.1:22->10.0.0.2:5555
        String local = name.contains("->") ? name.substring(0, name.indexOf("->")) : name;
        String[] addr = splitAddress(local);
        if (addr == null) {
            return null;
        }
        String state = m.group(10) == null ? "" : m.group(10);
        return new Sock(number, raw, m.group(8).toLowerCase(), addr[0], Integer.parseInt(addr[1]),
                normaliseState(state), m.group(1), "", exposure(addr[0]), "lsof");
    }

    private static List<Sock> grepable(int number, String raw, String text) {
        List<Sock> out = new ArrayList<>();
        if (!text.contains("Ports:") && !text.contains("/open/")) {
            return out;
        }
        Matcher m = GREPABLE_ENTRY.matcher(text);
        while (m.find()) {
            int port = Integer.parseInt(m.group(1));
            if (port > 65535) {
                continue;
            }
            String product = m.group(6) == null ? "" : m.group(6).strip();
            String version = m.group(7) == null ? "" : m.group(7).strip();
            String banner = (product + " " + version).strip();
            out.add(new Sock(number, raw, m.group(3), "", port, m.group(2), "",
                    banner, Exposure.REMOTE, "nmap-grepable"));
        }
        return out;
    }

    private static List<Sock> bare(int number, String raw, String text) {
        List<Sock> out = new ArrayList<>();
        String[] tokens = text.split("[,\\s]+");
        for (String token : tokens) {
            Matcher m = BARE.matcher(token.strip());
            if (!m.matches()) {
                return List.of();  // any junk on the line and we do not trust the whole line
            }
            String proto = m.group(1) != null ? m.group(1) : (m.group(3) != null ? m.group(3) : "tcp");
            int port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                return List.of();
            }
            out.add(new Sock(number, raw, proto, "", port, "listen", "", "",
                    Exposure.UNKNOWN, "bare"));
        }
        return out;
    }

    /** "0.0.0.0:22" / "[::]:22" / "*:22" / "10.0.0.1%eth0:68" -> {address, port}. */
    static String[] splitAddress(String token) {
        if (token == null) {
            return null;
        }
        String value = token.strip();
        int colon = value.lastIndexOf(':');
        if (colon <= 0 || colon == value.length() - 1) {
            return null;
        }
        String addr = value.substring(0, colon);
        String port = value.substring(colon + 1);
        if (!port.chars().allMatch(Character::isDigit)) {
            return null;
        }
        int portNumber;
        try {
            portNumber = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            return null;
        }
        if (portNumber < 0 || portNumber > 65535) {
            return null;
        }
        if (addr.startsWith("[") && addr.endsWith("]")) {
            addr = addr.substring(1, addr.length() - 1);
        }
        int percent = addr.indexOf('%');
        if (percent >= 0) {
            addr = addr.substring(0, percent);
        }
        return new String[]{addr, port};
    }

    static Exposure exposure(String addr) {
        if (addr == null || addr.isEmpty()) {
            return Exposure.UNKNOWN;
        }
        String a = addr.strip();
        if (a.equals("*") || a.equals("0.0.0.0") || a.equals("::") || a.equals("[::]")
                || a.equals("0") || a.equals("::ffff:0.0.0.0")) {
            return Exposure.WILDCARD;
        }
        if (a.equals("::1") || a.startsWith("127.") || a.equals("::ffff:127.0.0.1")
                || a.equalsIgnoreCase("localhost")) {
            return Exposure.LOOPBACK;
        }
        return Exposure.SPECIFIC;
    }

    /** ss prints users:(("sshd",pid=800,fd=3)) - pull out the program name. */
    private static String processFromSs(String field) {
        if (field == null || field.isBlank()) {
            return "";
        }
        Matcher m = Pattern.compile("\\(\\(\"([^\"]+)\"").matcher(field);
        if (m.find()) {
            return m.group(1);
        }
        return "";
    }

    private static String normaliseState(String state) {
        if (state == null) {
            return "";
        }
        String s = state.strip().toLowerCase().replace('_', '-');
        return switch (s) {
            case "unconn", "listen" -> "listen";
            case "estab", "established" -> "established";
            default -> s;
        };
    }

    /** True when a row represents something actually reachable/bound right now. */
    static boolean isOpen(Sock sock) {
        String state = sock.state();
        return state.isEmpty()
                || state.equals("listen")
                || state.startsWith("open");
    }
}
