# SilverDetector

Paste command output into an empty file. Get told what it is, what is normal, and what is not.

It works out which command you pasted on its own, names every entry ("tcp/22 — ssh, OpenSSH
remote login"), and flags the ones that do not belong. Nothing that is normal goes unexplained:
if a port or a SUID binary is fine, it says so and says what the thing does.

Everything it knows lives in tab-separated files under `data/`, so most of what you will ever
want to change is a row in a `.tsv`, not Java. When you want a whole new kind of input, that is
one class and one line in the registry — see [docs/ADDING_DETECTORS.md](docs/ADDING_DETECTORS.md).

## Quick start

```sh
git clone https://github.com/Magic-Cooki3/SilverDetector
cd SilverDetector
./build.sh                      # needs only a JDK - no Maven, no Gradle, no network

./bin/silverdetector            # opens an empty file in $EDITOR: paste, save, quit, read report
```

Other ways in, all equivalent:

```sh
ss -tulpn > /tmp/ports.txt
./bin/silverdetector /tmp/ports.txt         # a file you already have

find / -perm -4000 -ls 2>/dev/null | ./bin/silverdetector      # a pipe

./bin/silverdetector paste                  # the editor flow, said out loud
```

Put it on your `PATH` once and forget where it lives:

```sh
mkdir -p ~/.local/bin && ln -sf "$PWD/bin/silverdetector" ~/.local/bin/silverdetector
```

## What it reads today

| id       | input                                                              | what it tells you |
|----------|--------------------------------------------------------------------|-------------------|
| `setuid` | `find / -perm -4000 -ls`, `-perm -2000`, `-perm /6000`, bare paths, `ls -l`, `%m %p` | Which set-id binaries ship with the distro, which are GTFOBins escalation vectors, which are unknown, and which sit somewhere a package would never put one |
| `ports`  | `ss -tulpn`, `netstat -tulpn`, `nmap` (normal or `-oG`), `lsof -i`, a bare list of ports | What each port is for, whether it is bound to loopback or the whole network, whether the process holding it makes sense |
| `caps`   | `getcap -r / 2>/dev/null`                                          | What each capability actually grants, and whether the distro really ships that file with it |

Paste more than one at a time if you like — each format is detected and reported separately.

## Reading the report

```
  CRIT   tcp/4444 — metasploit-handler
         Metasploit's default handler/meterpreter port. If you started the handler this is
         you - if you did not, something is calling home.
         · this is a default port for remote-access tooling, not a stock service
         · bound on 0.0.0.0 (0.0.0.0 / :: - every interface)
         · process: nc
         · nc: netcat is listening. That is a raw socket relay, not a service - almost always
           a shell or a pivot.
         └ line 14: tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=3391,fd=3))
```

| level    | meaning |
|----------|---------|
| `CRIT`   | Privilege escalation vector, or a listener that has no business existing |
| `WARN`   | Off the beaten path: legacy service, unexpected set-id binary, cleartext protocol |
| `NOTICE` | Unrecognised or slightly off — look at it, but it is probably fine |
| `INFO`   | Context, not a problem |
| `OK`     | Expected, documented, boring. Printed so you can see what it is |

Exit codes, for scripting: `0` clean, `1` anomalies found, `2` usage or I/O error,
`3` nothing recognised the input. `--strict` counts `NOTICE` as a failure too.

Useful flags — `--help` has the rest:

```sh
silverdetector -q  out.txt      # anomalies only, hide the normal entries
silverdetector --json out.txt | jq '.runs[].findings[] | select(.anomaly)'
silverdetector -d ports out.txt # skip auto-detection, force a reader
silverdetector --list           # detectors, tables, row counts, search path
```

## Adding knowledge without touching Java

Every table is a tab-separated file with a header row. Add a row, run again — no rebuild:

```
data/ports.tsv         port -> name, risk class, description
data/listeners.tsv     process names that change the meaning of a port
data/suid_known.tsv    set-id binaries a stock install really ships
data/gtfobins.tsv      binaries that hand out root the moment they are SUID
data/capabilities.tsv  what each Linux capability grants
data/caps_known.tsv    files the distro ships with capabilities
```

Your own rows are better kept out of the repo, in
`~/.config/silverdetector/data/<table>.tsv`. That directory is read last, and a row there
**replaces** the built-in row with the same key, so you can disagree with anything shipped here
without editing it:

```sh
mkdir -p ~/.config/silverdetector/data
printf 'port\tproto\tservice\trisk\tdescription\n' >  ~/.config/silverdetector/data/ports.tsv
printf '9001\ttcp\tmy-c2\tnormal\tMy own listener, started deliberately.\n' \
    >> ~/.config/silverdetector/data/ports.tsv
```

Columns are separated by tabs; if a line has no tab in it at all, two-or-more spaces are
accepted instead, so a hand-typed row still parses. Lines starting with `#` are comments.

The `risk` column in `ports.tsv` is what drives severity:

| risk           | on loopback | reachable off-box |
|----------------|-------------|-------------------|
| `normal`       | OK          | OK                |
| `local`        | OK          | WARN              |
| `local-strict` | OK          | CRIT — unauthenticated by default (redis, docker api, X11, memcached…) |
| `sensitive`    | NOTICE      | WARN              |
| `dangerous`    | WARN        | CRIT              |
| `malware`      | CRIT        | CRIT              |

`silverdetector --list` prints every table, how many rows it loaded, and which files those rows
came from — the fastest way to confirm your override took effect.

## Adding a new kind of input

One class implementing `Detector`, one line in `DetectorRegistry`. A complete worked example —
Windows default folders, code and knowledge base — is in
[docs/ADDING_DETECTORS.md](docs/ADDING_DETECTORS.md), and the finished code ships in
`src/silverdetector/detect/WindowsFoldersDetector.java` ready to switch on.

## Layout

```
bin/silverdetector    launcher: paste mode, colour detection, auto-build
build.sh              javac + jar, nothing else
test.sh               regression suite - run it after changing a detector or a .tsv
data/*.tsv            the knowledge base
samples/*.txt         realistic pastes to try
src/silverdetector/
  Main.java           CLI
  core/               Detector, Document, Finding, Severity, Analyzer, Kb (the .tsv loader)
  detect/             the detectors themselves
  report/             text and JSON output
```

## Requirements

A JDK, and nothing else. Built with `--release 17` so the jar runs on anything from 17 up,
including the OpenJDK 26 on Athena OS. `./build.sh` is the whole build.

```sh
./test.sh             # 48 checks over the samples, detectors and override behaviour
```
