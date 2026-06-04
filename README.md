SysHarden v2.0 - Linux Server audit/hardening tool based on Python.
----------
Harden with "sudo python sysharden.py --harden"
#####
Audit with "sudo python sysharden.py --audit"
#####
Select categories to audit/harden with "sudo python sysharden.py --category [kernel,misc,etc..]"
#####
Output to JSON dump with results with "sudo python sysharden.py --json [location]"
#####
-----
Audit Categories
----
1. Kernel (kernel)
38 sysctl checks including: ASLR (randomize_va_space), kernel pointer restriction (kptr_restrict), ptrace scope, BPF hardening, SUID core dump restriction, protected links/fifos/regular files, IP forwarding, ICMP redirect rejection, source-routed packet rejection, reverse-path filtering, SYN cookies, TCP timestamps, SysRq, kernel panic settings, and more.

2. SSH (ssh)
23+ checks including: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, weak ciphers (CBC/ARCfour), weak MACs (MD5/SHA1), weak KEX algorithms, TCP forwarding, agent forwarding, StrictModes, banner configuration, LogLevel, and port obfuscation.

3. Users & Authentication (users)
UID 0 (only root), empty passwords, weak password hashes (MD5/old crypt), root PATH safety, password expiry (PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE), login retries/timeout, default umask, system accounts with login shells.

4. Filesystem (filesystem)
23+ checks including: critical file permissions (/etc/passwd, /etc/shadow, /etc/ssh/sshd_config, /etc/sudoers, GRUB config, SSH host keys), SUID/SGID binary audit (whitelist-based), world-writable files, world-writable directories missing sticky bit, unowned files, /tmp mount options (noexec,nosuid,nodev), /dev/shm mount options, /home nodev.

5. Services (services)
Detection of dangerous/obsolete services: telnet, rsh/rlogin/rexec, ftp/vsftpd, tftp, cups, avahi-daemon, bluetooth, rpcbind, nfs-server, nis, snmpd, inetd/xinetd, finger, talk, chargen/discard/echo/daytime.

Summary of all services listening on 0.0.0.0 or ::.

6. Firewall (firewall)
UFW active status, default deny incoming/routed, iptables/ip6tables default DROP policies (INPUT/FORWARD), nftables detection.

7. PAM (Pluggable Authentication Modules) (pam)
Password quality (minlen ≥12, dcredit/ucredit/lcredit/ocredit negative), retry ≤3, password history (pam_pwhistory remember ≥5), account lockout (pam_faillock deny ≤5), su restricted via pam_wheel, nullok prohibition.

8. Sudo (sudo)
sudoers syntax validation, NOPASSWD rule detection, overly broad ALL command grants, I/O logging configuration, version CVE awareness (Baron Samedit).

9. Packages (packages)
Security-relevant packages: unattended-upgrades, apt-listchanges, debsums, rkhunter, auditd, fail2ban, aide, apparmor.

Pending security updates detection, compiler tools (gcc, g++, cc) on production servers.

10. Logging & Auditing (logging)
syslog daemon (rsyslog/syslog-ng), auditd running + rule coverage (≥10 rules), critical audit rules (sudo, /etc/passwd, /etc/shadow, /etc/sudoers, faillog), log file permissions (auth.log, syslog), journald persistent storage.

11. AppArmor (apparmor)
AppArmor active status, enforce vs. complain mode profiles, loaded profile counts.

12. Miscellaneous (misc)
Core dumps disabled (limits.conf + systemd coredump), Ctrl+Alt+Del reboot masked, NTP/time synchronization, legal banner (/etc/issue.net), GRUB bootloader password, cron/at access control, world-writable cron directories, MOTD OS version leakage, dangerous kernel module blacklisting (cramfs, usb-storage, dccp, sctp, rds, tipc, etc.), DNS-over-TLS (systemd-resolved), IPv6 status.
