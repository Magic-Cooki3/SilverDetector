package silverdetector.detect;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Second-opinion lookup against the local {@code /etc/services}.
 *
 * <p>It has no risk information and no explanation, but it does know the IANA name for
 * thousands of ports the bundled table will never cover, so an unknown port can at least be
 * reported as "IANA calls this X".
 */
final class EtcServices {

    private static Map<String, String> cache;

    private EtcServices() {
    }

    /** IANA name for {@code port/proto}, or "" when unknown or /etc/services is unreadable. */
    static synchronized String name(int port, String proto) {
        if (cache == null) {
            cache = load();
        }
        String hit = cache.get(port + "/" + proto.toLowerCase());
        return hit == null ? "" : hit;
    }

    private static Map<String, String> load() {
        Map<String, String> map = new HashMap<>();
        for (String candidate : List.of("/etc/services", "/etc/inet/services")) {
            Path path = Paths.get(candidate);
            if (!Files.isReadable(path)) {
                continue;
            }
            try {
                for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                    String text = line.strip();
                    int hash = text.indexOf('#');
                    if (hash >= 0) {
                        text = text.substring(0, hash).strip();
                    }
                    if (text.isEmpty()) {
                        continue;
                    }
                    String[] fields = text.split("\\s+");
                    if (fields.length < 2 || !fields[1].contains("/")) {
                        continue;
                    }
                    String[] portProto = fields[1].split("/", 2);
                    try {
                        int port = Integer.parseInt(portProto[0]);
                        map.putIfAbsent(port + "/" + portProto[1].toLowerCase(), fields[0]);
                    } catch (NumberFormatException ignored) {
                        // not a port line
                    }
                }
                break;
            } catch (IOException ignored) {
                // fall through to the empty map; this lookup is a bonus, not a requirement
            }
        }
        return map;
    }
}
