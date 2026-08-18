# Adding a detector

Two levels of change. Pick the smallest one that does the job.

1. **New facts about something it already reads** — a port, a SUID binary, a capability.
   Add a row to a `.tsv` in `data/` (or in `~/.config/silverdetector/data/`). No code, no
   rebuild. Stop here; this is most changes.
2. **A new kind of command output** — Windows folders, cron jobs, `sudo -l`, kernel version,
   an `/etc/passwd` dump. That is one class and one line, described below.

---

## The contract

A detector implements `silverdetector.core.Detector`:

```java
String id();                          // "winfolders" - used by --detector and in JSON
String name();                        // "Windows folders" - the report header
String accepts();                     // what it eats, shown by --list
Detection sniff(Document doc);        // 0-100: is this paste mine?
List<Finding> analyze(Document doc);  // the actual answers
int order();                          // optional tie-break, lower runs first
```

Two rules make the difference between a useful detector and a noisy one:

- **`sniff` is cheap and never throws.** It only decides ownership. Score 0 when a paste is
  clearly not yours — a detector that claims everything makes auto-detection useless. Anything
  at 50 or above gets analysed, and several detectors can run on one paste (that is how a file
  holding both `ss` output and a `find` hunt gets both reports).
- **`analyze` emits a `Finding` for every row it understands, including the boring ones at
  `Severity.OK`.** Naming the normal stuff is half the point of the tool. A detector that only
  reports problems leaves you wondering whether it saw the rest.

`Document` gives you the paste: `contentLines()` is every line that is not blank and not a
`#` comment, each with its 1-based line number. Put that number in the `Finding` so the report
can point back at the evidence.

`Finding` is a record: severity, subject, label, detail, notes, evidence, line. Build one with
`Finding.of(...)` and add notes with `.note("...")` — each note becomes a dimmed bullet under
the entry. `.atLeast(Severity.WARN)` raises a finding without ever lowering it, which is how
one detector layers several checks over the same row.

---

## Worked example: Windows default folders

The whole thing ships in `src/silverdetector/detect/WindowsFoldersDetector.java`, with its
knowledge in `data/windows_paths.tsv` and a paste to try in `samples/windows-dir.txt`. It is
written but **not registered**, so it is a live example rather than an extra reader you did not
ask for.

### 1. Switch it on

In `src/silverdetector/core/DetectorRegistry.java`, uncomment one line:

```java
detectors.add(new WindowsFoldersDetector());
```

Then:

```sh
./build.sh
./bin/silverdetector samples/windows-dir.txt
```

```
▸ Windows folders  [winfolders]  Windows directory listing, 9 entries, confidence 81%

  NOTICE inetpub — IIS web root
         IIS is installed. On a workstation that is worth a question, and wwwroot is a
         favourite webshell location.
         · in the standard layout for Windows 2000 onwards
         └ line 13: 08/18/2026  10:22 AM    <DIR>          inetpub

  NOTICE intel-update — not a stock folder
         No row in windows_paths.tsv. That is normal for installed software and for anything a
         user created - but staging directories for exfiltration look exactly like this too,
         so confirm what put it there.
         └ line 15: 07/02/2026  03:14 AM    <DIR>          intel-update

  OK     Program Files — 64-bit applications
         Default install location for 64-bit software.
```

### 2. How it is put together

**The knowledge goes in a `.tsv`, not in the code.** `data/windows_paths.tsv` is keyed on the
lowercase folder name:

```
path	purpose	since	severity	description
windows	operating system	Windows NT onwards	OK	The OS itself: kernel, drivers, System32.
inetpub	IIS web root	Windows 2000 onwards	NOTICE	IIS is installed. On a workstation that is worth a question...
```

Loading it is one line, and the search path (jar → repo `data/` → `~/.config/silverdetector/data`)
comes for free:

```java
Table known = Kb.table("windows_paths");
Row row = known.first("inetpub");        // null when unknown
row.get("description");                  // "" when the column is missing - never null
Severity.parse(row.get("severity"), Severity.OK);
```

**`sniff` counts the lines it can parse** and scores on the ratio. Nothing more clever than
that is needed:

```java
public Detection sniff(Document doc) {
    List<String> names = names(doc);
    if (names.isEmpty()) {
        return Detection.NONE;
    }
    int lines = Math.max(1, doc.contentLines().size());
    int confidence = Math.min(95, 40 + (100 * names.size() / lines) * 55 / 100);
    return Detection.of(confidence, "Windows directory listing, %d entries", names.size());
}
```

**`analyze` looks each row up and answers in both directions** — a row in the table means
"here is what this is", no row means "here is why that might matter":

```java
Row row = known.first(normalise(name));
if (row != null) {
    finding = Finding.of(Severity.parse(row.get("severity"), Severity.OK),
            name, row.get("purpose"), row.get("description"),
            line.text().strip(), line.number())
            .note("in the standard layout for " + row.get("since"));
} else {
    finding = Finding.of(Severity.NOTICE, name, "not a stock folder",
            "No row in windows_paths.tsv. ...", line.text().strip(), line.number());
}
```

---

## Starting your own

```sh
cp src/silverdetector/detect/WindowsFoldersDetector.java \
   src/silverdetector/detect/CronJobsDetector.java
```

1. Rename the class, `id()`, `name()` and `accepts()`.
2. Replace the parsing regexes with whatever your command prints.
3. Create `data/cron_jobs.tsv` with a header row, and load it with `Kb.table("cron_jobs")`.
4. Add `detectors.add(new CronJobsDetector());` to `DetectorRegistry.all()`.
5. Drop a realistic paste in `samples/`, add a couple of `check` lines to `test.sh`, and run
   `./test.sh`.

`--detector <id>` forces yours to run while you are still tuning `sniff`, and `--json` shows
exactly what it produced without the formatting in the way.

### More examples already in the tree

The shipped detectors each show a technique you will probably want:

- **`CapabilitiesDetector`** — the shortest one. Parse, look up, emit. Start here.
- **`PortsDetector`** — one input, many formats (`ss`/`netstat`/`nmap`/`lsof`/bare). See how
  `Sockets` normalises them all into one record before analysis.
- **`ShadowDetector`** — a shared helper (`CryptHash`) and a lookup table (`hash_formats.tsv`)
  turning a raw hash into an actionable cracking mode. **`AdHashDetector`** does the same job for
  AD credential material (kerberoast / AS-REP tickets, NetNTLM captures, NTDS/SAM NT hashes): a
  regex-per-row table (`ad_hashes.tsv`) maps each hash to its `hashcat -m` mode, and the detector
  builds the command line — copy it when "recognise a hash, print how to crack (or pass, or
  relay) it" is the job.
- **`PasswdDetector`** — a cross-line pass (duplicate UID detection) before per-line findings.
- **`SudoDetector`** — a small stateful parser (Defaults block vs. command block), reuse of
  another detector's table (`gtfobins.tsv`), and version-range CVE checks in `SudoVersion`.
- **`KernelDetector` + `Version` + `ServiceCves`** — the automatic-CVE machinery. `Version`
  parses a dotted version out of messy text; `ServiceCves`/`kernel_cves.tsv` hold
  product/version ranges; the detector just parses a version and reports what lands in range.
  Copy this whenever "recognise a version, name its CVEs" is the job (`ftp`, `smb`, `http` all do).
- **`SmbDetector`** — carries state across lines (an nmap `smb-vuln-*` script id on one line, its
  `State: VULNERABLE` on another) and dedupes repeated findings.
- **`WindowsPrivescDetector` / `LinuxPrivescDetector` + the shared `Signatures` helper** — a
  *signature engine*: the detectors are thin, and all the knowledge is a regex-per-row table
  (`windows_signatures.tsv`, `linux_signatures.tsv`). This is the pattern to copy when "match a
  lot of independent tells in a big blob" is the job (a winPEAS/linPEAS-style dump). Adding a
  check is one TSV row; the code never changes. `Signatures` (load / anyMatch / scan / clean,
  including ANSI stripping) is the reusable core. **`AdDetector`** is a third detector on the same
  engine, over `ad_signatures.tsv` — Active Directory enum/attack tooling (NetExec, BloodHound,
  Certipy, Impacket, Responder, ...) — and shows how to gate `sniff` on a tool-name allowlist so a
  single stray match doesn't claim an unrelated paste.
- **`NmapScriptsDetector` + `nmap_scripts.tsv`** — a *stateful* reader: it tracks the current NSE
  script id across `|` lines and fires on a later `State: VULNERABLE`, with a keyed table for the
  known scripts and a generic catch for the rest. Copy it when the meaning of a line depends on an
  earlier line, and you want unknown-but-clearly-bad results surfaced too.
- **`SqlmapDetector` + `sqlmap_steps.tsv` / `sqlmap_dbms.tsv`** — a *walkthrough* detector: instead
  of severity-sorted findings it returns an ordered sequence of steps (the report prints findings
  in the order you return them — no re-sort), each reconstructing a command from what it parsed out
  of the paste. Copy it when the answer is "here is what to do next, in order", not "here is what is
  wrong". The two tables split the generic ladder from the per-DBMS specifics.

Copy whichever is closest to your input's shape. Note how many of these **share a table**: add a
GTFOBins binary, a writable directory, or a CVE range once and every detector that reads that
table gets it — that sharing is the point, so prefer extending a table over hard-coding.

### Things worth knowing

- **Severity is a ladder, not a label.** `OK → INFO → NOTICE → WARN → CRITICAL`. The process
  exit code is derived from the worst finding, so a detector that cries `CRITICAL` over
  ordinary output makes the tool unusable in a script.
- **`Kb` caches tables** for the life of the process, so calling `Kb.table("...")` inside a
  loop is fine.
- **A detector that throws does not kill the run** — the exception is caught and reported as a
  `WARN` against the detector itself. Handy, but do not lean on it.
- **A detector that scores well but finds nothing is dropped from the report**, so an
  over-eager `sniff` costs you less than you would think. It still costs the user a confusing
  header, though.
- **Keep judgement in the `.tsv` and mechanism in the code.** Anything you might reasonably
  change your mind about later — a name, a description, how alarming something is — belongs in
  a column, where you can override it from `~/.config` without a rebuild.
