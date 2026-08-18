package silverdetector.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import silverdetector.detect.CapabilitiesDetector;
import silverdetector.detect.CronDetector;
import silverdetector.detect.FtpDetector;
import silverdetector.detect.GroupsDetector;
import silverdetector.detect.HttpDetector;
import silverdetector.detect.KernelDetector;
import silverdetector.detect.LinuxPrivescDetector;
import silverdetector.detect.NmapScriptsDetector;
import silverdetector.detect.PasswdDetector;
import silverdetector.detect.PortsDetector;
import silverdetector.detect.SetuidDetector;
import silverdetector.detect.ShadowDetector;
import silverdetector.detect.SmbDetector;
import silverdetector.detect.SqlmapDetector;
import silverdetector.detect.SudoDetector;
import silverdetector.detect.WindowsFoldersDetector;
import silverdetector.detect.WindowsPrivescDetector;

/**
 * The list of everything SilverDetector knows how to read.
 *
 * <p>ADD YOUR DETECTOR HERE - one {@code detectors.add(...)} line below and it is live:
 * auto-detection, {@code --detector <id>}, {@code --list} and JSON output all pick it up.
 * See {@code docs/ADDING_DETECTORS.md}.
 */
public final class DetectorRegistry {

    private DetectorRegistry() {
    }

    public static List<Detector> all() {
        List<Detector> detectors = new ArrayList<>();

        detectors.add(new WindowsPrivescDetector()); // winPEAS / whoami /priv / Windows enum
        detectors.add(new LinuxPrivescDetector());   // linPEAS / Linux enum (writable files, NFS, docker, CVE tags)
        detectors.add(new SetuidDetector());        // find / -perm -4000 (and -2000)
        detectors.add(new GroupsDetector());        // id
        detectors.add(new SudoDetector());          // sudo -l
        detectors.add(new SmbDetector());           // smbclient -L / enum4linux / nmap smb-*
        detectors.add(new FtpDetector());           // FTP banners  (auto CVE match)
        detectors.add(new NmapScriptsDetector());   // nmap NSE script results (-sC / -A / --script)
        detectors.add(new PortsDetector());         // ss / netstat / nmap / lsof
        detectors.add(new CapabilitiesDetector());  // getcap -r /
        detectors.add(new HttpDetector());          // curl -i / raw HTTP  (auto CVE match)
        detectors.add(new SqlmapDetector());        // sqlmap output -> guided SQLi walkthrough
        detectors.add(new CronDetector());          // crontab -l, /etc/crontab
        detectors.add(new PasswdDetector());        // cat /etc/passwd
        detectors.add(new ShadowDetector());        // cat /etc/shadow
        detectors.add(new KernelDetector());        // uname -a  (auto CVE match)

        // Worked example from docs/ADDING_DETECTORS.md. Uncomment to switch it on.
        // detectors.add(new WindowsFoldersDetector());

        // ---- your detectors go here -------------------------------------------------

        detectors.sort(Comparator.comparingInt(Detector::order).thenComparing(Detector::id));
        return detectors;
    }

    /** Looks a detector up by id, case-insensitively. Returns null when there is no such id. */
    public static Detector byId(String id) {
        for (Detector detector : all()) {
            if (detector.id().equalsIgnoreCase(id)) {
                return detector;
            }
        }
        return null;
    }

    public static List<String> ids() {
        List<String> ids = new ArrayList<>();
        for (Detector detector : all()) {
            ids.add(detector.id());
        }
        return ids;
    }
}
