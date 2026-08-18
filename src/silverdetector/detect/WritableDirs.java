package silverdetector.detect;

import silverdetector.core.Kb;
import silverdetector.core.Row;

/**
 * "Is this path somewhere a lower-privileged user can write?" - the shared answer behind two
 * findings: a SUID binary in such a place (planted backdoor) and a root cron running a script
 * from one (free privilege escalation). The list is {@code data/writable_dirs.tsv}.
 */
final class WritableDirs {

    private WritableDirs() {
    }

    /** The matching writable root for {@code path}, or null when it is nowhere risky. */
    static String match(String path) {
        if (path == null || path.isEmpty()) {
            return null;
        }
        for (Row row : Kb.table("writable_dirs").rows()) {
            String dir = row.get("dir");
            if (!dir.isEmpty() && (path.equals(dir) || path.startsWith(dir + "/"))) {
                return dir;
            }
        }
        return null;
    }
}
