package silverdetector.detect;

import java.util.ArrayList;
import java.util.List;

import silverdetector.core.Finding;
import silverdetector.core.Severity;

/**
 * A parsed {@code sudo -V} / {@code sudo version} string, so the detector can flag the famous
 * version-specific holes. Comparison is over {@code major.minor.micro} plus the {@code pN} patch
 * level, e.g. {@code 1.9.5p1}.
 *
 * <p>Only the headline CVEs are encoded - enough for a learner to recognise "oh, this build is
 * the Baron Samedit one" and go read about it. It is not a substitute for a real vulnerability
 * scan.
 */
final class SudoVersion {

    private final int[] parts;   // {major, minor, micro, patch}
    private final String raw;

    private SudoVersion(int[] parts, String raw) {
        this.parts = parts;
        this.raw = raw;
    }

    static SudoVersion parse(String text) {
        String v = text.strip().toLowerCase();
        int patch = 0;
        int p = v.indexOf('p');
        if (p >= 0) {
            patch = parseIntSafe(v.substring(p + 1));
            v = v.substring(0, p);
        }
        String[] dotted = v.split("\\.");
        int[] parts = {0, 0, 0, patch};
        for (int i = 0; i < 3 && i < dotted.length; i++) {
            parts[i] = parseIntSafe(dotted[i]);
        }
        return new SudoVersion(parts, text.strip());
    }

    /** CVE-2021-3156 "Baron Samedit": heap overflow in sudoedit, root from any local user. */
    boolean baronSamedit() {
        return inRange(1, 8, 2, 0, 1, 8, 31, 2) || inRange(1, 9, 0, 0, 1, 9, 5, 1);
    }

    /** CVE-2019-18634 pwfeedback stack overflow (only when pwfeedback is also enabled). */
    boolean pwfeedbackVulnerable() {
        return inRange(1, 7, 1, 0, 1, 8, 30, 999);
    }

    /** CVE-2019-14287 runas -u#-1 bypass. */
    boolean runasNegationBypass() {
        return compare(1, 8, 28, 0) < 0;
    }

    /** CVE-2023-22809 sudoedit EDITOR extra-file. */
    boolean sudoeditExtraFile() {
        return inRange(1, 8, 0, 0, 1, 9, 12, 1);
    }

    List<Finding> findings() {
        List<Finding> out = new ArrayList<>();
        if (baronSamedit()) {
            out.add(Finding.of(Severity.CRITICAL, "sudo " + raw, "Baron Samedit (CVE-2021-3156)",
                    "This sudo version is in the range vulnerable to CVE-2021-3156: a heap overflow "
                    + "in sudoedit's argument handling that gives root from any local account, no "
                    + "sudo rights required. Public exploits exist.",
                    "", 0).note("next: confirm with 'sudoedit -s Y' (a crash/segfault-shaped error "
                    + "means vulnerable), then use a public PoC"));
        }
        if (sudoeditExtraFile()) {
            out.add(Finding.of(Severity.NOTICE, "sudo " + raw, "sudoedit EDITOR trick (CVE-2023-22809)",
                    "If this user has any sudoedit rule, this version let an attacker append extra "
                    + "files to edit through the EDITOR/VISUAL variable - including files the rule "
                    + "never listed.", "", 0));
        }
        return out;
    }

    private boolean inRange(int aMaj, int aMin, int aMic, int aPat,
                            int bMaj, int bMin, int bMic, int bPat) {
        return compare(aMaj, aMin, aMic, aPat) >= 0 && compare(bMaj, bMin, bMic, bPat) <= 0;
    }

    private int compare(int maj, int min, int mic, int pat) {
        int[] other = {maj, min, mic, pat};
        for (int i = 0; i < 4; i++) {
            if (parts[i] != other[i]) {
                return Integer.compare(parts[i], other[i]);
            }
        }
        return 0;
    }

    private static int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s.replaceAll("\\D", "").isEmpty() ? "0" : s.replaceAll("\\D", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @Override
    public String toString() {
        return raw;
    }
}
