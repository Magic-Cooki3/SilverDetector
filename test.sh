#!/bin/sh
# Regression tests. Run ./test.sh after changing a detector or a .tsv file.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
# Always rebuild, so the tests run against the current source and data - never a stale jar left
# over from an older version (that produces confusing "detector runs but finds nothing" failures).
./build.sh >/dev/null || { echo "test.sh: build failed - fix the compile error above" >&2; exit 1; }

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
echo "sudo -l"
check "sudo output picks the sudo detector"      says "read with: sudo" samples/sudo-l.txt
check "sudo does not double-match as passwd"     silent_about "\[passwd\]" samples/sudo-l.txt
check "NOPASSWD find via sudo is critical"       says "CRIT   sudo root: find" samples/sudo-l.txt
check "the exploit next-step is shown"           says "next: see GTFOBins entry for 'find'" samples/sudo-l.txt
check "env_keep LD_PRELOAD is critical"          says "CRIT   Defaults env_keep" samples/sudo-l.txt
check "good defaults are called normal"          says "OK     Defaults (hardening)" samples/sudo-l.txt
check "runas negation flags CVE-2019-14287"      says "CVE-2019-14287" samples/sudo-l.txt
check "(ALL) ALL is a full-root critical" \
    sh -c 'printf "User x may run the following commands on h:\n    (ALL : ALL) ALL\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "run ANY command"'
check "Baron Samedit version is flagged" \
    sh -c 'printf "Sudo version 1.8.31p1\nUser x may run the following commands on h:\n    (root) /usr/bin/vi\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "CVE-2021-3156"'
check "a patched sudo is not flagged Samedit" \
    sh -c 'printf "Sudo version 1.9.15p5\nUser x may run the following commands on h:\n    (root) /usr/bin/vi\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -qv "Baron Samedit"'
check "no sudo rights is reported, not crashed" \
    sh -c 'printf "User x is not in the sudoers file.  This incident will be reported.\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "no sudo rights"'

echo
echo "/etc/passwd"
check "passwd output picks the passwd detector"  says "read with: passwd" samples/etc-passwd.txt
check "a second UID 0 account is critical"       says "CRIT   toor" samples/etc-passwd.txt
check "a hash in passwd is critical"             says "HASH is stored in world-readable" samples/etc-passwd.txt
check "an empty password is critical"            says "CRIT   guest" samples/etc-passwd.txt
check "a human account is named as a target"     says "INFO   victim" samples/etc-passwd.txt
check "root itself is normal"                    says "OK     root" samples/etc-passwd.txt
check "a service account with a shell warns"     says "WARN   backupsvc" samples/etc-passwd.txt
check "www-data (nologin) is normal"             says "OK     www-data" samples/etc-passwd.txt

echo
echo "/etc/shadow"
check "shadow output picks the shadow detector"  says "read with: shadow" samples/etc-shadow.txt
check "shadow does not double-match as passwd"   silent_about "\[passwd\]" samples/etc-shadow.txt
check "an empty hash is critical"                says "CRIT   backdoor" samples/etc-shadow.txt
check "a DES hash is a weak-hash warning"        says "WARN   legacy" samples/etc-shadow.txt
check "an MD5 hash is a weak-hash warning"       says "WARN   olduser" samples/etc-shadow.txt
check "a yescrypt hash is normal"                says "OK     root" samples/etc-shadow.txt
check "a sha512 hash is normal"                  says "OK     victim" samples/etc-shadow.txt
check "the hashcat mode is shown"                says "hashcat -m 1800" samples/etc-shadow.txt
check "a locked account is normal"               says "OK     daemon" samples/etc-shadow.txt
check "reading shadow is itself noted"           says "you are reading the shadow file" samples/etc-shadow.txt

echo
echo "group membership (id)"
check "id output picks the groups detector"      says "read with: groups" samples/id.txt
check "docker group is critical"                 says "CRIT   docker" samples/id.txt
check "disk group is critical"                   says "CRIT   disk" samples/id.txt
check "sudo group warns"                         says "WARN   sudo" samples/id.txt
check "adm group is a notice"                    says "NOTICE adm" samples/id.txt
check "cdrom group is normal"                    says "OK     cdrom" samples/id.txt
check "the escalation step is shown"             says "docker run -v /:/mnt" samples/id.txt

echo
echo "cron"
check "crontab picks the cron detector"          says "read with: cron" samples/crontab.txt
check "cron does not misread find -ls"           silent_about "\[cron\]" samples/find-perm-4000.txt
check "a root cron in a writable dir is critical" says "CRIT   cron: /home/victim/backup.sh" samples/crontab.txt
check "a writable cron PATH warns"               says "WARN   cron PATH" samples/crontab.txt
check "a wildcard tar in cron is called out"     says "wildcard privesc" samples/crontab.txt
check "run-parts is treated as normal"           says "OK" samples/crontab.txt

echo
echo "kernel (auto CVE match)"
check "uname picks the kernel detector"          says "read with: kernel" samples/uname.txt
check "Dirty Pipe matches 5.15.0"                says "CVE-2022-0847" samples/uname.txt
check "a matched CVE names the exploit"          says "Dirty Pipe" samples/uname.txt
check "the mainline range is shown"              says "affects mainline" samples/uname.txt
check "an ancient kernel matches Dirty COW" \
    sh -c 'printf "Linux box 3.2.0-4-amd64 #1 SMP Debian x86_64 GNU/Linux\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "CVE-2016-5195"'
check "a current kernel matches nothing known" \
    sh -c 'printf "Linux box 6.9.0-1-amd64 #1 SMP x86_64 GNU/Linux\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "No local-privesc CVE"'

echo
echo "ftp (auto CVE match)"
check "an ftp banner picks the ftp detector"     says "read with: ftp" samples/ftp-banner.txt
check "vsftpd 2.3.4 matches its backdoor CVE"    says "CVE-2011-2523" samples/ftp-banner.txt
check "anonymous ftp is called out"              says "anonymous FTP access allowed" samples/ftp-banner.txt

echo
echo "smb"
check "smbclient output picks the smb detector"  says "read with: smb" samples/smbclient.txt
check "Samba 4.6.2 matches SambaCry"             says "CVE-2017-7494" samples/smbclient.txt
check "no signing is a relay warning"            says "SMB signing not required" samples/smbclient.txt
check "anonymous smb access warns"               says "guest/anonymous SMB access" samples/smbclient.txt
check "a non-default share is noticed"           says "non-default share: backups" samples/smbclient.txt
check "an SMB1-disabled line is not flagged" \
    sh -c 'printf "SMB1 disabled -- no workgroup available\n\tSharename  Type  Comment\n\tdata       Disk  x\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -qv "SMBv1 in use"'
check "MS17-010 vulnerable is critical" \
    sh -c 'printf "Host script results:\n|   smb-vuln-ms17-010:\n|     State: VULNERABLE\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "EternalBlue"'

echo
echo "http (headers / methods / auto CVE match)"
check "an http response picks the http detector" says "read with: http" samples/http-headers.txt
check "Apache 2.4.49 matches CVE-2021-41773"     says "CVE-2021-41773" samples/http-headers.txt
check "OpenSSL 1.0.1e matches Heartbleed"        says "CVE-2014-0160" samples/http-headers.txt
check "a flagless cookie is called out"          says "missing flags" samples/http-headers.txt
check "wildcard CORS is noticed"                 says "wildcard CORS" samples/http-headers.txt
check "missing security headers are listed"      says "missing security headers" samples/http-headers.txt
check "a PUT request is flagged" \
    sh -c 'printf "PUT /shell.php HTTP/1.1\nHost: x\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "PUT request"'
check "a hardened response is clean" \
    sh -c 'printf "HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=63072000\nContent-Security-Policy: default-src '"'"'self'"'"'\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "security headers present"'

echo
echo "sqlmap walkthrough"
check "sqlmap output picks the sqlmap detector" says "read with: sqlmap" samples/sqlmap.txt
check "the injection is confirmed"              says "SQL injection CONFIRMED" samples/sqlmap.txt
check "the DBMS is named"                        says "against PostgreSQL" samples/sqlmap.txt
check "the UNION column count is parsed"         says "5 columns" samples/sqlmap.txt
check "the visible UNION column is identified"   says "column #2" samples/sqlmap.txt
check "the command is rebuilt with the cookie"   says "PHPSESSID=dg069s7ndaegcrhdp72funt677" samples/sqlmap.txt
check "the manual UNION payload is shown"        says "UNION SELECT NULL,version()" samples/sqlmap.txt
check "step 8 names the COPY FROM PROGRAM RCE"   says "COPY sd FROM PROGRAM" samples/sqlmap.txt
check "the CVE for postgres RCE is cited"        says "CVE-2019-9193" samples/sqlmap.txt
check "the manual lesson explains column discovery" says "How the manual injection works" samples/sqlmap.txt
check "the steps come out in order" \
    sh -c 'out=$(SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar samples/sqlmap.txt 2>/dev/null); s1=$(printf "%s" "$out" | grep -n "Step 1:" | head -1 | cut -d: -f1); s8=$(printf "%s" "$out" | grep -n "Step 8:" | head -1 | cut -d: -f1); [ -n "$s1" ] && [ -n "$s8" ] && [ "$s1" -lt "$s8" ]'
check "a MySQL sqlmap paste gets MySQL manual SQL" \
    sh -c 'printf "sqlmap -u \"http://t/p.php?id=1\"\nParameter: id (GET)\n    Type: UNION query\n    Title: Generic UNION query (NULL) - 3 columns\n    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(0x71),NULL-- -\nback-end DBMS: MySQL\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "group_concat"'
check "a DBA-confirmed paste offers --passwords" \
    sh -c 'printf "sqlmap -u \"http://t/p.php?id=1\"\nParameter: id (GET)\n    Type: UNION query\n    Title: Generic UNION query (NULL) - 3 columns\n    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(1),NULL-- -\ncurrent user is DBA: True\nback-end DBMS: MySQL\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q -- "--passwords"'

echo
echo "windows privesc (winPEAS / checklist)"
check "winpeas output picks the winprivesc detector" says "read with: winprivesc" samples/winpeas.txt
check "whoami /priv is recognised"               says "read with: winprivesc" samples/whoami-priv.txt
check "SeImpersonate is critical"                says "CRIT   SeImpersonatePrivilege" samples/whoami-priv.txt
check "the Potato technique is named"            says "Potato" samples/whoami-priv.txt
check "AlwaysInstallElevated is critical"        says "CRIT   AlwaysInstallElevated" samples/winpeas.txt
check "autologon password is critical"           says "Autologon credentials" samples/winpeas.txt
check "GPP cpassword is critical"                says "Group Policy Preferences password" samples/winpeas.txt
check "SAM backup is critical"                   says "SAM / SYSTEM / NTDS backup" samples/winpeas.txt
check "WDigest cleartext is a warning"           says "WDigest stores cleartext" samples/winpeas.txt
check "the checklist item is cited"              says "checklist: AlwaysInstallElevated" samples/winpeas.txt
check "a benign privilege is normal"             says "OK     SeChangeNotifyPrivilege" samples/whoami-priv.txt
check "winprivesc does not fire on a dir listing" silent_about "\[winprivesc\]" samples/windows-dir.txt
check "winprivesc does not fire on /etc/passwd"  silent_about "\[winprivesc\]" samples/etc-passwd.txt
check "SeManageVolumePrivilege is flagged" \
    sh -c 'printf "SeManageVolumePrivilege        Perform volume maintenance tasks   Enabled\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "SeManageVolume"'
check "Administrators membership is critical" \
    sh -c 'printf "GROUP INFORMATION\n-----------------\nGroup Name  Type\nBUILTIN\\\\Administrators  Alias  Mandatory group, Enabled\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "privileged group"'

echo
echo "linux privesc (linPEAS / checklist)"
check "linpeas picks the linprivesc detector"    says "\[linprivesc\]" samples/linpeas.txt
check "writable /etc/passwd is critical"         says "Writable /etc/passwd" samples/linpeas.txt
check "no_root_squash NFS is critical"           says "no_root_squash" samples/linpeas.txt
check "the docker socket is critical"            says "Docker socket reachable" samples/linpeas.txt
check "a PwnKit CVE tag is recognised"           says "PwnKit" samples/linpeas.txt
check "an SSH private key is flagged"            says "SSH private key" samples/linpeas.txt
check "linprivesc does not fire on the SUID pkexec sample" silent_about "\[linprivesc\]" samples/find-perm-4000.txt
check "linprivesc does not run on a winPEAS dump" silent_about "\[linprivesc\]" samples/winpeas.txt

echo
echo "peas acceptance (both engines + structured detectors)"
check "linpeas output is accepted"               says "read with:" samples/linpeas.txt
check "linpeas kernel section -> Dirty COW"      says "CVE-2016-5195" samples/linpeas.txt
check "linpeas sudo section -> GTFOBins find"    says "find via sudo" samples/linpeas.txt
check "linpeas SUID section -> planted shell"    says "CRIT   /tmp/.hidden/bash" samples/linpeas.txt
check "linpeas does not run the windows engine"  silent_about "\[winprivesc\]" samples/linpeas.txt

echo
echo "nmap NSE script results"
check "a scripted scan picks the nmapscripts detector" says "\[nmapscripts\]" samples/nmap-scripts.txt
check "ssl-heartbleed is explained"              says "Heartbleed" samples/nmap-scripts.txt
check "ms17-010 via NSE is critical"             says "EternalBlue" samples/nmap-scripts.txt
check "an unknown vuln script is still flagged"  says "nse: smb-vuln-cve-2077-9999" samples/nmap-scripts.txt
check "http-methods is surfaced"                 says "HTTP methods allowed" samples/nmap-scripts.txt
check "smb-os-discovery is surfaced"             says "SMB OS discovery" samples/nmap-scripts.txt
check "a NOT VULNERABLE script is not flagged" \
    sh -c 'printf "| smb-vuln-ms17-010:\n|_    State: NOT VULNERABLE\n| http-title: Home\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -qv "EternalBlue"'
check "a plain port scan does not run nmapscripts" silent_about "\[nmapscripts\]" samples/nmap.txt

echo
echo "active directory (enumeration & attack tooling)"
check "netexec output picks the ad detector"      says "read with: ad" samples/netexec.txt
check "a Pwn3d! host is critical"                 says "Local admin / Pwn3d!" samples/netexec.txt
check "valid domain credentials are critical"     says "Valid domain credentials" samples/netexec.txt
check "a lockout during spraying warns"           says "Account lockout hit" samples/netexec.txt
check "ldapsearch picks the ad detector"          says "\[ad\]" samples/ldapsearch.txt
check "an SPN account is kerberoastable"          says "kerberoastable" samples/ldapsearch.txt
check "constrained delegation is critical"        says "Constrained delegation (S4U)" samples/ldapsearch.txt
check "MachineAccountQuota is flagged"            says "MachineAccountQuota" samples/ldapsearch.txt
check "bloodhound GenericAll is critical"         says "GenericAll over an object" samples/bloodhound.txt
check "bloodhound DCSync rights is critical"      says "DCSync rights" samples/bloodhound.txt
check "RBCD is recognised"                        says "Resource-based constrained delegation" samples/bloodhound.txt
check "shadow credentials edge is flagged"        says "Shadow Credentials" samples/bloodhound.txt
check "RBCD is not double-read as constrained"    silent_about "Constrained delegation (S4U)" samples/bloodhound.txt
check "certipy ESC1 is critical"                  says "ESC1 - enrollee supplies" samples/certipy.txt
check "certipy ESC8 relay is critical"            says "ESC8 - NTLM relay" samples/certipy.txt
check "kerberoasting is recognised"               says "Kerberoasting" samples/kerberoast.txt
check "AS-REP roasting is recognised"             says "AS-REP roasting" samples/kerberoast.txt
check "a domain credential dump is critical"      says "Domain credential dump" samples/secretsdump.txt
check "responder captures a NetNTLM hash"         says "Responder poisoning captured" samples/responder.txt
check "ad does not fire on a plain ss table"      silent_about "\[ad\]" samples/ss-tulpn.txt
check "ad does not fire on winPEAS output"        silent_about "\[ad\]" samples/winpeas.txt

echo
echo "ad credential material (adhash -> crack modes)"
check "a kerberoast ticket picks the adhash detector" says "\[adhash\]" samples/kerberoast.txt
check "a TGS-REP ticket maps to hashcat 13100"    says "hashcat -m 13100" samples/kerberoast.txt
check "an AS-REP ticket maps to hashcat 18200"    says "hashcat -m 18200" samples/kerberoast.txt
check "NTDS NT hashes map to hashcat 1000"        says "hashcat -m 1000" samples/secretsdump.txt
check "NT hashes recommend pass-the-hash"         says "pass-the-hash" samples/secretsdump.txt
check "the krbtgt hash is flagged for golden tickets" says "forges Golden Tickets" samples/secretsdump.txt
check "a NetNTLMv2 capture maps to hashcat 5600"  says "hashcat -m 5600" samples/responder.txt
check "adhash counts the hashes it captured"      says "5 hashes captured" samples/secretsdump.txt
check "adhash does not fire on /etc/shadow"       silent_about "\[adhash\]" samples/etc-shadow.txt
check "a bare krb5tgs paste is understood" \
    sh -c 'printf "\$krb5tgs\$23\$*svc\$CORP\$MSSQLSvc/h*\$abc\$def123456789abcdef\n" | SILVERDETECTOR_COLOR=0 java -jar silverdetector.jar 2>/dev/null | grep -q "hashcat -m 13100"'

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
echo "self-update (--update)"
check "--update with no arg prints usage" \
    sh -c 'bin/silverdetector --update 2>&1 | grep -q "usage: silverdetector --update"'
check "--update rejects a missing file" \
    sh -c 'bin/silverdetector --update /no/such/file.zip >/dev/null 2>&1; [ $? = 2 ]'
# build a GitHub-style zip of this tree, then update a throwaway copy from it
updtmp=$tmp/upd
mkdir -p "$updtmp/pkg/SilverDetector-x"
cp -a src data bin docs build.sh test.sh README.md "$updtmp/pkg/SilverDetector-x/" 2>/dev/null
echo "# update-test-marker" >> "$updtmp/pkg/SilverDetector-x/data/groups.tsv"
( cd "$updtmp/pkg" && { command -v zip >/dev/null 2>&1 && zip -qr ../pkg.zip SilverDetector-x || jar cf ../pkg.zip SilverDetector-x; } ) >/dev/null 2>&1
mkdir -p "$updtmp/inst"
cp -a src data bin docs build.sh test.sh README.md "$updtmp/inst/"
check "--update swaps files and rebuilds from a local zip" \
    sh -c '"'"$updtmp"'/inst/bin/silverdetector" --update "'"$updtmp"'/pkg.zip" >/dev/null 2>&1 && grep -q update-test-marker "'"$updtmp"'/inst/data/groups.tsv"'
check "--update leaves a restorable backup" \
    sh -c 'ls "'"$updtmp"'/inst/.backups/"*.tgz >/dev/null 2>&1'
check "the updated install still runs" \
    sh -c '"'"$updtmp"'/inst/bin/silverdetector" --no-color samples/whoami-priv.txt 2>/dev/null | grep -q winprivesc'
check "--update rejects a non-SilverDetector archive" \
    sh -c 'mkdir -p "'"$updtmp"'/junk/x"; echo hi > "'"$updtmp"'/junk/x/a.txt"; ( cd "'"$updtmp"'/junk" && { command -v zip >/dev/null 2>&1 && zip -qr ../junk.zip x || jar cf ../junk.zip x; } ) >/dev/null 2>&1; bin/silverdetector --update "'"$updtmp"'/junk.zip" >/dev/null 2>&1; [ $? = 1 ]'

echo
echo "----------------------------------------"
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" = 0 ]
