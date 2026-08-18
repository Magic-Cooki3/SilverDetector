package silverdetector.core;

import java.util.ArrayList;
import java.util.List;

/**
 * One line of the report: a thing that was found, what it is, and whether it is normal.
 *
 * @param severity how alarming it is
 * @param subject  the identity of the thing, e.g. "tcp/22" or "/usr/bin/find"
 * @param label    what it is called, e.g. "ssh - OpenSSH remote login"
 * @param detail   what it does / why it is flagged, in plain English
 * @param notes    extra observations (bind address, owner, mode bits, ...)
 * @param evidence the raw input line this came from
 * @param line     1-based line number in the input, or 0 if not tied to a line
 */
public record Finding(Severity severity,
                      String subject,
                      String label,
                      String detail,
                      List<String> notes,
                      String evidence,
                      int line) {

    public Finding {
        notes = notes == null ? List.of() : List.copyOf(notes);
        subject = subject == null ? "" : subject;
        label = label == null ? "" : label;
        detail = detail == null ? "" : detail;
        evidence = evidence == null ? "" : evidence;
    }

    public static Finding of(Severity severity, String subject, String label, String detail,
                             String evidence, int line) {
        return new Finding(severity, subject, label, detail, List.of(), evidence, line);
    }

    /** Returns a copy with one more note appended. Nulls and blanks are ignored. */
    public Finding note(String note) {
        if (note == null || note.isBlank()) {
            return this;
        }
        List<String> merged = new ArrayList<>(notes);
        merged.add(note);
        return new Finding(severity, subject, label, detail, merged, evidence, line);
    }

    /** Returns a copy at a higher severity; never downgrades. */
    public Finding atLeast(Severity floor) {
        return severity.atLeast(floor)
                ? this
                : new Finding(floor, subject, label, detail, notes, evidence, line);
    }

    public boolean isAnomaly() {
        return severity.isAnomaly();
    }
}
