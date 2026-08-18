#!/bin/sh
# Regression tests. Run ./test.sh after changing a detector or a .tsv file.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
[ -f silverdetector.jar ] || ./build.sh >/dev/null

sd() {
    SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar "$@" 2>/dev/null
}

pass=0
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check() {
    name=$1
    shift
    if "$@"; then
        pass=$((pass + 1))
        printf '  ok    %s\n' "$name"
    else
        fail=$((fail + 1))
        printf '  FAIL  %s\n' "$name"
    fi
}

# exit_is <expected> <file/args...>
exit_is() {
    want=$1
    shift
    got=0
    sd "$@" >/dev/null || got=$?
    [ "$got" = "$want" ] || { echo "        expected exit $want, got $got" >&2; return 1; }
}

# says <pattern> <args...>
says() {
    pattern=$1
    shift
    sd "$@" | grep -q -- "$pattern" || { echo "        no match for: $pattern" >&2; return 1; }
}

# silent_about <pattern> <args...>
silent_about() {
    pattern=$1
    shift
    if sd "$@" | grep -q -- "$pattern"; then
        echo "        unexpected match for: $pattern" >&2
        return 1
    fi
    return 0
}

echo
echo "detection"
check "ss table picks the ports detector"        says "read with: ports" samples/ss-tulpn.txt
check "find -ls picks the setuid detector"       says "read with: setuid" samples/find-perm-4000.txt
check "getcap picks the caps detector"           says "read with: caps" samples/getcap.txt
check "getcap does not also match setuid"        silent_about "\[setuid\]" samples/getcap.txt
check "nmap output picks the ports detector"     says "read with: ports" samples/nmap.txt
check "one paste can hold two formats"           says "read with: setuid, ports" samples/mixed.txt
check "--detector overrides detection"           says "\[ports\]" --detector ports samples/ss-tulpn.txt

echo
echo "ports"
check "netcat on 4444 is critical"               says "CRIT   tcp/4444" samples/ss-tulpn.txt
check "telnet is critical when exposed"          says "CRIT   tcp/23" samples/ss-tulpn.txt
check "exposed redis is critical"                says "CRIT   tcp/6379" samples/ss-tulpn.txt
check "loopback postgres is normal"              says "OK     tcp/5432" samples/ss-tulpn.txt
check "ssh is normal and named"                  says "OK     tcp/22 — ssh" samples/ss-tulpn.txt
check "port 2000 is explained"                   says "tcp/2000 — cisco-sccp" samples/ss-tulpn.txt
check "port 4000 is explained"                   says "tcp/4000 — terabase" samples/ss-tulpn.txt
check "v4+v6 rows collapse into one finding"     says "2 matching rows" samples/ss-tulpn.txt
check "unknown high loopback port is only info"  says "INFO   tcp/44321" samples/ss-tulpn.txt
check "the listening process is named"           says "netcat is listening" samples/ss-tulpn.txt

echo
echo "setuid / setgid"
check "a SUID shell in /tmp is critical"         says "CRIT   /tmp/.cache/bash" samples/find-perm-4000.txt
check "SUID find is critical"                    says "CRIT   /usr/bin/find" samples/find-perm-4000.txt
check "SUID nmap is critical"                    says "CRIT   /usr/bin/nmap" samples/find-perm-4000.txt
check "stock SUID passwd is normal"              says "OK     /usr/bin/passwd" samples/find-perm-4000.txt
check "pkexec carries the PwnKit note"           says "CVE-2021-4034" samples/find-perm-4000.txt
check "unknown SUID binary warns"                says "WARN   /usr/local/bin/backup-helper" samples/find-perm-4000.txt
check "SGID tty write is normal"                 says "OK     /usr/bin/write" samples/mixed.txt
check "unknown SGID binary warns"                says "WARN   /usr/local/bin/dstat" samples/mixed.txt

echo
echo "capabilities"
check "cap_setuid on python is critical"         says "CRIT   /usr/bin/python3.12" samples/getcap.txt
check "cap_net_raw on ping is normal"            says "OK     /usr/bin/ping" samples/getcap.txt
check "shipped cap_setuid on newuidmap is fine"  says "OK     /usr/bin/newuidmap" samples/getcap.txt

echo
echo "input handling"
printf '22\n80\n443\n8080\n' > "$tmp/bare.txt"
check "a bare list of ports is understood"       says "tcp/443 — https" "$tmp/bare.txt"

printf 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=880,fd=3))\n' > "$tmp/clean.txt"
printf 'tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=1044,fd=7))\n' >> "$tmp/clean.txt"
check "a clean paste exits 0"                    exit_is 0 "$tmp/clean.txt"
check "a clean paste says so"                    says "nothing abnormal found" "$tmp/clean.txt"
check "anomalies exit 1"                         exit_is 1 samples/ss-tulpn.txt

printf 'the quick brown fox\njumps over the lazy dog\n' > "$tmp/junk.txt"
check "unrecognised input exits 3"               exit_is 3 "$tmp/junk.txt"
check "unrecognised input suggests --detector"   says "detector" "$tmp/junk.txt"

: > "$tmp/empty.txt"
check "an empty paste is reported, not crashed"  says "input is empty" "$tmp/empty.txt"

printf '# just a comment\n\n' > "$tmp/comments.txt"
check "comment-only paste counts as empty"       says "input is empty" "$tmp/comments.txt"

check "stdin works"                              sh -c 'SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar < samples/ss-tulpn.txt 2>/dev/null | grep -q "tcp/4444"'
check "--json emits findings"                    says '"severity"' --json samples/ss-tulpn.txt
check "--json has no ANSI codes"                 silent_about "$(printf '\033')" --json samples/ss-tulpn.txt
check "--list shows the tables"                  says "ports.tsv" --list
check "--list shows the detectors"               says "setuid" --list
check "--help works"                             exit_is 0 --help
check "a bad detector id exits 2"                exit_is 2 --detector nope samples/ss-tulpn.txt
check "a missing file exits 2"                   exit_is 2 "$tmp/does-not-exist.txt"
check "--strict promotes notices to failure"     exit_is 1 --strict samples/getcap.txt

echo
echo "knowledge base overrides"
mkdir -p "$tmp/data"
printf 'port\tproto\tservice\trisk\tdescription\n' > "$tmp/data/ports.tsv"
printf '22\ttcp\tssh-hardened\tnormal\tOur SSH, port-knocked and key-only.\n' >> "$tmp/data/ports.tsv"
check "a user table overrides a bundled row" \
    sh -c 'SILVERDETECTOR_DATA='"$tmp"'/data SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar samples/ss-tulpn.txt 2>/dev/null | grep -q "ssh-hardened"'
check "an override does not drop other rows" \
    sh -c 'SILVERDETECTOR_DATA='"$tmp"'/data SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar samples/ss-tulpn.txt 2>/dev/null | grep -q "tcp/80 — http"'

printf 'port\tproto\tservice\trisk\tdescription\n9999\ttcp\n' > "$tmp/data/broken.tsv"
check "a malformed table does not crash the run"  exit_is 1 samples/ss-tulpn.txt

echo
echo "----------------------------------------"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" = 0 ]
