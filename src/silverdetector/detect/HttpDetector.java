package silverdetector.detect;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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
 * HTTP requests and responses - what {@code curl -i}, Burp, or a saved response shows.
 *
 * <p>Covers the three things the request said to check:
 * <ul>
 *   <li>the request line's method - {@code PUT}/{@code DELETE}/{@code TRACE} and friends</li>
 *   <li>response headers - the {@code Server}/{@code X-Powered-By} versions (matched to CVEs),
 *       the security headers that are missing, cookie flags, and CORS</li>
 *   <li>default/disclosure tells that hand an attacker the stack for free</li>
 * </ul>
 */
public final class HttpDetector implements Detector {

    private static final Pattern STATUS = Pattern.compile("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})\\b.*");
    private static final Pattern REQUEST = Pattern.compile(
            "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH|CONNECT)\\s+(\\S+)\\s+HTTP/\\d.*");
    private static final Pattern HEADER = Pattern.compile("^([A-Za-z][A-Za-z0-9-]*):\\s?(.*)$");
    // product/version tokens inside a Server or X-Powered-By value
    private static final Pattern PRODUCT = Pattern.compile(
            "([A-Za-z][A-Za-z0-9_+.-]*)/(\\d+\\.\\d+(?:\\.\\d+)?[\\w.]*)");

    private static final Set<String> KNOWN_HEADERS = Set.of(
            "server", "x-powered-by", "content-type", "set-cookie", "location", "www-authenticate",
            "access-control-allow-origin", "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "cache-control", "date", "connection",
            "allow", "public", "x-aspnet-version", "content-length", "authorization", "host");

    @Override
    public String id() {
        return "http";
    }

    @Override
    public String name() {
        return "HTTP request / response";
    }

    @Override
    public String accepts() {
        return "curl -i / -I output, a raw HTTP request or response, Burp copy";
    }

    @Override
    public int order() {
        return 35;
    }

    @Override
    public Detection sniff(Document doc) {
        boolean status = false;
        boolean request = false;
        int headers = 0;
        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();
            if (STATUS.matcher(text).matches()) {
                status = true;
            } else if (REQUEST.matcher(text).matches()) {
                request = true;
            } else {
                Matcher h = HEADER.matcher(text);
                if (h.matches() && KNOWN_HEADERS.contains(h.group(1).toLowerCase())) {
                    headers++;
                }
            }
        }
        if (!status && !request && headers < 2) {
            return Detection.NONE;
        }
        int confidence = (status || request ? 60 : 30) + Math.min(35, headers * 8);
        String what = status ? "HTTP response" : request ? "HTTP request" : "HTTP headers";
        return Detection.of(Math.min(96, confidence), what);
    }

    @Override
    public List<Finding> analyze(Document doc) {
        Table headerKb = Kb.table("http_headers");
        List<Finding> findings = new ArrayList<>();
        Map<String, String> headers = new LinkedHashMap<>();
        List<String> cookies = new ArrayList<>();
        boolean isResponse = false;

        for (Document.Line line : doc.contentLines()) {
            String text = line.text().strip();

            Matcher request = REQUEST.matcher(text);
            if (request.matches()) {
                findings.add(assessMethod(request.group(1), request.group(2), text, line.number()));
                continue;
            }
            if (STATUS.matcher(text).matches()) {
                isResponse = true;
                continue;
            }
            Matcher header = HEADER.matcher(text);
            if (header.matches()) {
                String name = header.group(1).toLowerCase();
                String value = header.group(2).strip();
                if (name.equals("set-cookie")) {
                    cookies.add(value);
                } else {
                    headers.putIfAbsent(name, value);
                }
            }
        }

        // Version disclosure + CVE match from Server / X-Powered-By.
        for (String field : List.of("server", "x-powered-by", "x-aspnet-version")) {
            if (headers.containsKey(field)) {
                findings.add(assessVersionHeader(field, headers.get(field), headerKb));
            }
        }

        findings.addAll(cookieFindings(cookies));

        String cors = headers.get("access-control-allow-origin");
        if ("*".equals(cors)) {
            findings.add(Finding.of(Severity.NOTICE, "http/cors", "wildcard CORS policy",
                    "Access-Control-Allow-Origin: * lets any origin read responses. Harmless for "
                    + "truly public data; a real problem if the endpoint returns anything per-user.",
                    "Access-Control-Allow-Origin: *", 0));
        }

        String auth = headers.get("www-authenticate");
        if (auth != null && auth.toLowerCase().contains("basic")) {
            findings.add(Finding.of(Severity.NOTICE, "http/auth", "HTTP Basic authentication",
                    "The server asks for HTTP Basic auth. Credentials are base64, not encrypted - "
                    + "over plain HTTP they are effectively cleartext, and Basic is brute-forceable.",
                    "WWW-Authenticate: " + auth, 0));
        }

        String allow = headers.getOrDefault("allow", headers.getOrDefault("public", ""));
        findings.addAll(methodHeaderFindings(allow));

        if (isResponse) {
            findings.add(missingSecurityHeaders(headers, headerKb));
        }

        findings.removeIf(f -> f == null);
        findings.sort(Comparator
                .comparingInt((Finding f) -> f.severity().rank()).reversed()
                .thenComparing(Finding::subject));
        return findings;
    }

    private Finding assessMethod(String method, String path, String evidence, int line) {
        Set<String> risky = Set.of("PUT", "DELETE", "TRACE", "CONNECT", "PATCH");
        if (risky.contains(method)) {
            String why = switch (method) {
                case "PUT" -> "PUT can upload files to the server - a web shell if the path is served.";
                case "DELETE" -> "DELETE can remove server-side resources.";
                case "TRACE" -> "TRACE echoes the request back (Cross-Site Tracing); it should be off.";
                case "CONNECT" -> "CONNECT can turn the server into a proxy to other hosts.";
                default -> "PATCH modifies resources; confirm it is meant to be exposed.";
            };
            return Finding.of(Severity.NOTICE, "http/" + method, method + " request",
                    "A " + method + " request to " + path + ". " + why, evidence, line);
        }
        return Finding.of(Severity.OK, "http/" + method, method + " request",
                "A standard " + method + " request to " + path + ".", evidence, line);
    }

    private Finding assessVersionHeader(String field, String value, Table headerKb) {
        Row meta = headerKb.first(field);
        Severity base = meta != null ? Severity.parse(meta.get("severity"), Severity.NOTICE) : Severity.NOTICE;
        String detail = meta != null && meta.has("description") ? meta.get("description")
                : "Discloses server/stack version information.";

        List<ServiceCves.Hit> allHits = new ArrayList<>();
        Matcher m = PRODUCT.matcher(value);
        Set<String> products = new LinkedHashSet<>();
        while (m.find()) {
            String product = normaliseProduct(m.group(1));
            products.add(m.group(1) + "/" + m.group(2));
            allHits.addAll(ServiceCves.match(product, m.group(2)));
        }

        Severity severity = base.max(ServiceCves.worst(allHits));
        Finding finding = Finding.of(severity, "http/" + field,
                headerLabel(field) + (allHits.isEmpty() ? " discloses version" : " - known vulnerable"),
                detail, field + ": " + value, 0);
        if (!products.isEmpty()) {
            finding = finding.note("advertised: " + String.join(", ", products));
        }
        for (String note : ServiceCves.notes(allHits)) {
            finding = finding.note(note);
        }
        return finding;
    }

    private List<Finding> cookieFindings(List<String> cookies) {
        List<Finding> out = new ArrayList<>();
        for (String cookie : cookies) {
            String lower = cookie.toLowerCase();
            List<String> missing = new ArrayList<>();
            if (!lower.contains("httponly")) {
                missing.add("HttpOnly (JavaScript can read it - XSS steals the session)");
            }
            if (!lower.contains("secure")) {
                missing.add("Secure (it will be sent over plain HTTP)");
            }
            if (!lower.contains("samesite")) {
                missing.add("SameSite (sent cross-site - CSRF exposure)");
            }
            String name = cookie.contains("=") ? cookie.substring(0, cookie.indexOf('=')) : cookie;
            if (!missing.isEmpty()) {
                Finding f = Finding.of(Severity.NOTICE, "http/cookie:" + name.strip(),
                        "cookie '" + name.strip() + "' missing flags",
                        "The cookie is set without: " + String.join("; ", missing) + ".",
                        "Set-Cookie: " + cookie, 0);
                out.add(f);
            }
        }
        return out;
    }

    private List<Finding> methodHeaderFindings(String allow) {
        List<Finding> out = new ArrayList<>();
        if (allow == null || allow.isBlank()) {
            return out;
        }
        String upper = allow.toUpperCase();
        List<String> risky = new ArrayList<>();
        for (String method : List.of("PUT", "DELETE", "TRACE", "CONNECT")) {
            if (upper.contains(method)) {
                risky.add(method);
            }
        }
        if (!risky.isEmpty()) {
            out.add(Finding.of(Severity.NOTICE, "http/methods", "risky methods advertised",
                    "The server advertises " + String.join(", ", risky) + " in its allowed methods. "
                    + "Test whether they actually work - an enabled PUT is often a file upload.",
                    "Allow: " + allow, 0).note("next: curl -X PUT http://host/path -d @shell"));
        }
        return out;
    }

    private Finding missingSecurityHeaders(Map<String, String> headers, Table headerKb) {
        List<String> missing = new ArrayList<>();
        for (Row row : headerKb.rows()) {
            if (!row.is("kind", "security")) {
                continue;
            }
            String name = row.get("header");
            if (!headers.containsKey(name) && Severity.parse(row.get("severity"), Severity.INFO)
                    .atLeast(Severity.NOTICE)) {
                missing.add(name);
            }
        }
        if (missing.isEmpty()) {
            return Finding.of(Severity.OK, "http/headers", "security headers present",
                    "The key hardening headers are set. Good.", "", 0);
        }
        return Finding.of(Severity.NOTICE, "http/headers", "missing security headers",
                "The response is missing: " + String.join(", ", missing) + ". None is a hole on its "
                + "own, but together they signal an app that has not been hardened, and each removes "
                + "a layer (clickjacking, MIME sniffing, transport downgrade, XSS defence-in-depth).",
                "", 0);
    }

    private static String normaliseProduct(String name) {
        String n = name.toLowerCase();
        return switch (n) {
            case "apache", "apache2", "httpd" -> "apache";
            case "nginx" -> "nginx";
            case "php" -> "php";
            case "openssl" -> "openssl";
            case "microsoft-iis", "iis" -> "microsoft-iis";
            case "coyote", "tomcat", "apache-coyote" -> "tomcat";
            default -> n;
        };
    }

    private static String headerLabel(String field) {
        return switch (field) {
            case "server" -> "Server header";
            case "x-powered-by" -> "X-Powered-By";
            case "x-aspnet-version" -> "X-AspNet-Version";
            default -> field;
        };
    }
}
