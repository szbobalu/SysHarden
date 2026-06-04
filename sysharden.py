#!/usr/bin/env python3
# sysaudit.py — Debian/Ubuntu expert system security audit + hardening tool
# Requires root. Usage:
#   sudo python3 sysaudit.py --audit [--verbose] [--json FILE] [--category ssh,kernel,...]
#   sudo python3 sysaudit.py --harden [--category kernel,ssh,...] [--dry-run]
#   sudo python3 sysaudit.py --audit --harden

import argparse
import glob
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

TOOL_VERSION = "2.0.0"
BACKUP_DIR   = Path("/root/.sysaudit_backups")

# terminal colors
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def clr(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + C.RESET

class Severity(Enum):
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1
    PASS     = 0

SEV_COLOR = {
    Severity.CRITICAL: C.RED + C.BOLD,
    Severity.HIGH:     C.RED,
    Severity.MEDIUM:   C.YELLOW,
    Severity.LOW:      C.CYAN,
    Severity.INFO:     C.BLUE,
    Severity.PASS:     C.GREEN,
}

SEV_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MED ",
    Severity.LOW:      "LOW ",
    Severity.INFO:     "INFO",
    Severity.PASS:     "PASS",
}

@dataclass
class R:
    # single audit result
    id:       str
    category: str
    title:    str
    severity: Severity
    passed:   bool
    detail:   str
    fix:      Optional[str]  = None
    refs:     list[str]      = field(default_factory=list)


# ─── utility layer ────────────────────────────────────────────────────────────

def run(cmd: str, timeout: int = 15) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def read_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(errors="replace")
    except Exception:
        return None

def sysctl_get(key: str) -> Optional[str]:
    rc, out, _ = run(f"sysctl -n {key} 2>/dev/null")
    return out.strip() if rc == 0 and out else None

def sysctl_set(key: str, value: str) -> bool:
    return run(f"sysctl -w {key}={value}")[0] == 0

def file_mode(path: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except Exception:
        return None

def file_owner(path: str) -> Optional[tuple[int, int]]:
    try:
        s = os.stat(path)
        return s.st_uid, s.st_gid
    except Exception:
        return None

def backup(path: str) -> bool:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(path)
    if not src.exists():
        return False
    dst = BACKUP_DIR / f"{src.name}.{int(time.time())}.bak"
    try:
        shutil.copy2(str(src), str(dst))
        return True
    except Exception:
        return False

def sysctl_persist(key: str, value: str, conf: str = "/etc/sysctl.d/99-sysaudit.conf") -> None:
    p = Path(conf)
    content = p.read_text() if p.exists() else ""
    pat = re.compile(rf"^\s*{re.escape(key)}\s*=.*", re.MULTILINE)
    new_line = f"{key} = {value}"
    if pat.search(content):
        content = pat.sub(new_line, content)
    else:
        content += f"\n{new_line}\n"
    p.write_text(content)

def login_defs_get(key: str) -> Optional[str]:
    content = read_file("/etc/login.defs")
    if not content:
        return None
    m = re.search(rf"^\s*{re.escape(key)}\s+(\S+)", content, re.MULTILINE)
    return m.group(1) if m else None

def parse_sshd_config(path: str = "/etc/ssh/sshd_config") -> dict[str, str]:
    cfg: dict[str, str] = {}
    content = read_file(path) or ""
    # expand Include directives
    for match in re.finditer(r"^\s*Include\s+(.+)", content, re.IGNORECASE | re.MULTILINE):
        for inc in glob.glob(match.group(1)):
            content += "\n" + (read_file(inc) or "")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1]
    return cfg

def shadow_entries() -> list[dict]:
    entries = []
    content = read_file("/etc/shadow")
    if not content:
        return entries
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) < 8:
            continue
        entries.append({
            "name":    parts[0],
            "hash":    parts[1],
            "last":    parts[2],
            "min":     parts[3],
            "max":     parts[4],
            "warn":    parts[5],
            "inactive":parts[6],
            "expire":  parts[7],
        })
    return entries

def active_service(*names: str) -> bool:
    for name in names:
        rc, out, _ = run(f"systemctl is-active {name} 2>/dev/null")
        if rc == 0 and out.strip() == "active":
            return True
    return False

def pkg_installed(name: str) -> bool:
    rc, out, _ = run(f"dpkg -l {name} 2>/dev/null")
    return rc == 0 and any(line.startswith("ii") for line in out.splitlines())


# ─── audit check functions ────────────────────────────────────────────────────

def check_kernel() -> list[R]:
    results: list[R] = []

    sysctl_targets = [
        # (id, key, expected, severity, rationale, persist_fix)
        ("K01", "kernel.randomize_va_space",              "2", Severity.HIGH,
         "ASLR full randomization prevents memory-layout-based exploits.",
         True),
        ("K02", "kernel.dmesg_restrict",                  "1", Severity.MEDIUM,
         "Limits kernel ring buffer reads to root, blocking info disclosure.",
         True),
        ("K03", "kernel.kptr_restrict",                   "2", Severity.HIGH,
         "Hides kernel symbol addresses from all users (kptr=1 hides from non-root only).",
         True),
        ("K04", "kernel.yama.ptrace_scope",               "1", Severity.MEDIUM,
         "Restricts ptrace to parent processes, blocking credential-stealing tools.",
         True),
        ("K05", "kernel.perf_event_paranoid",             "3", Severity.LOW,
         "Disables all perf_event access for unprivileged users.",
         True),
        ("K06", "kernel.unprivileged_bpf_disabled",       "1", Severity.HIGH,
         "eBPF is a significant attack surface; restrict to CAP_BPF/CAP_SYS_ADMIN.",
         True),
        ("K07", "kernel.core_uses_pid",                   "1", Severity.LOW,
         "Appends PID to core filenames, preventing overwrite races.",
         True),
        ("K08", "net.core.bpf_jit_harden",                "2", Severity.MEDIUM,
         "Mitigates BPF JIT spraying attacks.",
         True),
        ("K09", "fs.suid_dumpable",                       "0", Severity.HIGH,
         "Prevents SUID/privileged processes from writing core dumps.",
         True),
        ("K10", "fs.protected_hardlinks",                 "1", Severity.MEDIUM,
         "Blocks hardlink-based TOCTOU attacks (file must be owned or writable).",
         True),
        ("K11", "fs.protected_symlinks",                  "1", Severity.MEDIUM,
         "Blocks symlink TOCTOU attacks in world-writable sticky dirs.",
         True),
        ("K12", "fs.protected_fifos",                     "2", Severity.MEDIUM,
         "Prevents opening FIFOs in world-writable sticky dirs by non-owners.",
         True),
        ("K13", "fs.protected_regular",                   "2", Severity.MEDIUM,
         "Prevents opening regular files in world-writable sticky dirs by non-owners.",
         True),
        ("K14", "net.ipv4.ip_forward",                    "0", Severity.HIGH,
         "IP forwarding must be disabled on non-router hosts.",
         True),
        ("K15", "net.ipv6.conf.all.forwarding",           "0", Severity.HIGH,
         "IPv6 forwarding must be disabled on non-router hosts.",
         True),
        ("K16", "net.ipv4.conf.all.send_redirects",       "0", Severity.MEDIUM,
         "Non-router hosts must not send ICMP redirects.",
         True),
        ("K17", "net.ipv4.conf.default.send_redirects",   "0", Severity.MEDIUM,
         "Applies send_redirects=0 to new interfaces.",
         True),
        ("K18", "net.ipv4.conf.all.accept_redirects",     "0", Severity.MEDIUM,
         "Rejects ICMP redirects that could manipulate routing.",
         True),
        ("K19", "net.ipv4.conf.default.accept_redirects", "0", Severity.MEDIUM,
         "Applies accept_redirects=0 to new interfaces.",
         True),
        ("K20", "net.ipv6.conf.all.accept_redirects",     "0", Severity.MEDIUM,
         "Rejects IPv6 ICMP redirects.",
         True),
        ("K21", "net.ipv4.conf.all.accept_source_route",  "0", Severity.HIGH,
         "Source-routed packets allow the sender to specify the path; enables firewall bypass.",
         True),
        ("K22", "net.ipv4.conf.default.accept_source_route","0", Severity.HIGH,
         "Applies source_route=0 to new interfaces.",
         True),
        ("K23", "net.ipv6.conf.all.accept_source_route",  "0", Severity.HIGH,
         "Rejects IPv6 source-routed packets.",
         True),
        ("K24", "net.ipv4.conf.all.log_martians",         "1", Severity.LOW,
         "Logs spoofed/unroutable packets; useful for IDS.",
         True),
        ("K25", "net.ipv4.conf.default.log_martians",     "1", Severity.LOW,
         "Applies log_martians=1 to new interfaces.",
         True),
        ("K26", "net.ipv4.icmp_echo_ignore_broadcasts",   "1", Severity.LOW,
         "Ignoring ICMP broadcast echos prevents smurf amplification.",
         True),
        ("K27", "net.ipv4.icmp_ignore_bogus_error_responses","1", Severity.LOW,
         "Drops malformed ICMP error responses.",
         True),
        ("K28", "net.ipv4.tcp_syncookies",                "1", Severity.HIGH,
         "SYN cookies protect against SYN flood DoS.",
         True),
        ("K29", "net.ipv4.conf.all.rp_filter",            "1", Severity.MEDIUM,
         "Reverse-path filtering drops packets with a spoofed source IP.",
         True),
        ("K30", "net.ipv4.conf.default.rp_filter",        "1", Severity.MEDIUM,
         "Applies rp_filter=1 to new interfaces.",
         True),
        ("K31", "net.ipv4.tcp_rfc1337",                   "1", Severity.LOW,
         "Drops RST packets for TIME_WAIT sockets, preventing hijacking.",
         True),
        ("K32", "net.ipv4.tcp_timestamps",                "0", Severity.LOW,
         "TCP timestamps can reveal system uptime and assist in OS fingerprinting.",
         True),
        ("K33", "kernel.sysrq",                           "0", Severity.MEDIUM,
         "Magic SysRq keys allow low-level OS actions; disable on production hosts.",
         True),
        ("K34", "net.ipv4.conf.all.secure_redirects",     "0", Severity.MEDIUM,
         "Blocks ICMP redirects even from default-route gateways.",
         True),
        ("K35", "net.ipv6.conf.all.accept_ra",            "0", Severity.MEDIUM,
         "Rejects IPv6 Router Advertisements; prevents rogue RA attacks.",
         True),
        ("K36", "net.ipv6.conf.default.accept_ra",        "0", Severity.MEDIUM,
         "Applies accept_ra=0 to new interfaces.",
         True),
        ("K37", "kernel.panic",                           "60", Severity.LOW,
         "Auto-reboot after kernel panic within 60s (improves availability).",
         True),
        ("K38", "kernel.panic_on_oops",                   "1", Severity.LOW,
         "Panic on kernel oops; prevents processes continuing in corrupt state.",
         True),
    ]

    for check_id, key, expected, severity, rationale, persist in sysctl_targets:
        val = sysctl_get(key)
        if val is None:
            results.append(R(
                id=check_id, category="kernel", title=key,
                severity=Severity.INFO, passed=False,
                detail=f"{key}: not readable (module absent or unsupported kernel).",
                fix=f"sysctl -w {key}={expected}"
            ))
            continue
        passed = val.strip() == expected
        results.append(R(
            id=check_id, category="kernel", title=key,
            severity=severity if not passed else Severity.PASS,
            passed=passed,
            detail=rationale + f"\n           current: {key} = {val}" +
                   ("" if passed else f"  (expected: {expected})"),
            fix=None if passed else f"sysctl -w {key}={expected}  →  persist in /etc/sysctl.d/99-sysaudit.conf"
        ))

    return results


def check_ssh() -> list[R]:
    results: list[R] = []
    cfg = parse_sshd_config()

    if not active_service("ssh", "sshd"):
        results.append(R(
            id="S00", category="ssh", title="SSH daemon not running",
            severity=Severity.INFO, passed=True,
            detail="sshd not active — SSH checks skipped."
        ))
        return results

    def chk(cid, title, key, expected, sev, detail):
        raw = cfg.get(key.lower())
        val = raw.lower() if raw else None
        passed = val == expected.lower()
        results.append(R(
            id=cid, category="ssh", title=title,
            severity=sev if not passed else Severity.PASS,
            passed=passed,
            detail=f"{detail}\n           sshd_config: {key} = {raw or '(default)'}",
            fix=f"Set '{key} {expected}' in /etc/ssh/sshd_config"
        ))

    chk("S01", "PermitRootLogin disabled",
        "PermitRootLogin", "no", Severity.CRITICAL,
        "Direct root SSH login eliminates an entire authentication layer.")

    chk("S02", "PasswordAuthentication disabled",
        "PasswordAuthentication", "no", Severity.HIGH,
        "Password auth is vulnerable to brute-force; enforce key-only auth.")

    chk("S03", "PermitEmptyPasswords disabled",
        "PermitEmptyPasswords", "no", Severity.CRITICAL,
        "Accounts with empty passwords must never be allowed SSH access.")

    chk("S04", "X11Forwarding disabled",
        "X11Forwarding", "no", Severity.MEDIUM,
        "X11 forwarding exposes the local X socket; disable unless required.")

    chk("S05", "HostbasedAuthentication disabled",
        "HostbasedAuthentication", "no", Severity.HIGH,
        "Host-based auth bypasses per-user credentials; obsolete and insecure.")

    chk("S06", "IgnoreRhosts yes",
        "IgnoreRhosts", "yes", Severity.HIGH,
        ".rhosts/.shosts are insecure; ignore them unconditionally.")

    chk("S07", "UsePAM yes",
        "UsePAM", "yes", Severity.MEDIUM,
        "PAM provides account controls, lockout, and session auditing.")

    chk("S08", "AllowAgentForwarding disabled",
        "AllowAgentForwarding", "no", Severity.MEDIUM,
        "Agent forwarding leaks auth keys if the intermediate server is compromised.")

    chk("S09", "PermitUserEnvironment disabled",
        "PermitUserEnvironment", "no", Severity.MEDIUM,
        "User-supplied env vars in ~/.ssh/environment can bypass restrictions.")

    chk("S10", "GSSAPIAuthentication disabled",
        "GSSAPIAuthentication", "no", Severity.LOW,
        "GSSAPI/Kerberos is rarely needed; disable to reduce attack surface.")

    chk("S11", "AllowTcpForwarding disabled",
        "AllowTcpForwarding", "no", Severity.MEDIUM,
        "TCP forwarding turns SSH into an open proxy; disable unless explicitly needed.")

    chk("S12", "ClientAliveCountMax <= 3",
        "ClientAliveCountMax", "3", Severity.LOW,
        "Combined with ClientAliveInterval, limits idle session persistence.")

    chk("S13", "StrictModes yes",
        "StrictModes", "yes", Severity.MEDIUM,
        "Checks key file ownership/permissions before accepting auth.")

    # numeric range checks
    for cid, key, default, max_ok, sev, detail, fix_val in [
        ("S14", "maxauthtries",    6,  4, Severity.MEDIUM,
         "Limits auth attempts per connection, slowing brute-force.",  4),
        ("S15", "logingracetime",  120, 60, Severity.LOW,
         "Limits time window for unauthenticated connections.",         60),
        ("S16", "clientaliveinterval", 0, 300, Severity.LOW,
         "Detects stale sessions and disconnects them.",                300),
    ]:
        raw = cfg.get(key)
        try:
            val = int(re.sub(r"[^\d]", "", raw)) if raw else default
        except ValueError:
            val = default
        if cid == "S16":
            passed = 0 < val <= max_ok
        else:
            passed = val <= max_ok
        results.append(R(
            id=cid, category="ssh", title=f"{key} in safe range",
            severity=sev if not passed else Severity.PASS,
            passed=passed,
            detail=detail + f"\n           {key} = {raw or f'(default: {default})'}",
            fix=f"Set '{key} {fix_val}' in /etc/ssh/sshd_config"
        ))

    # cipher/MAC/kex weak-algorithm checks
    weak_ciphers = {
        "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
        "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
        "cast128-cbc", "rijndael-cbc@lysator.liu.se"
    }
    weak_macs = {
        "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
        "umac-64@openssh.com", "hmac-ripemd160"
    }
    weak_kex = {
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1", "gss-gex-sha1-"
    }

    for cid, key, weak_set, fix_str in [
        ("S17", "ciphers",       weak_ciphers,
         "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"),
        ("S18", "macs",          weak_macs,
         "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"),
        ("S19", "kexalgorithms", weak_kex,
         "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"),
    ]:
        raw = cfg.get(key.lower(), "")
        if not raw:
            results.append(R(
                id=cid, category="ssh", title=f"SSH {key} explicitly hardened",
                severity=Severity.INFO, passed=False,
                detail=f"{key} not set — defaults depend on OpenSSH version; explicit config recommended.",
                fix=f"Set '{fix_str}' in /etc/ssh/sshd_config"
            ))
            continue
        found = weak_set & {a.strip().lower() for a in raw.split(",")}
        passed = len(found) == 0
        results.append(R(
            id=cid, category="ssh", title=f"No weak {key}",
            severity=Severity.HIGH if not passed else Severity.PASS,
            passed=passed,
            detail=f"{key} = {raw}" + (f"\n           WEAK ALGORITHMS: {', '.join(found)}" if not passed else ""),
            fix=f"Set '{fix_str}' in /etc/ssh/sshd_config"
        ))

    # banner
    banner = cfg.get("banner")
    passed = banner is not None and banner.strip().lower() not in {"", "none"}
    results.append(R(
        id="S20", category="ssh", title="SSH login banner configured",
        severity=Severity.LOW if not passed else Severity.PASS,
        passed=passed,
        detail=f"Banner = {banner or '(not set)'}. Legal banners deter unauthorized access and establish notice.",
        fix="Set 'Banner /etc/issue.net' and populate /etc/issue.net with a legal warning"
    ))

    # loglevel
    ll = cfg.get("loglevel", "INFO").upper()
    passed = ll in {"INFO", "VERBOSE"}
    results.append(R(
        id="S21", category="ssh", title="SSH LogLevel INFO or VERBOSE",
        severity=Severity.LOW if not passed else Severity.PASS,
        passed=passed,
        detail=f"LogLevel = {ll}",
        fix="Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config"
    ))

    # default port
    port = cfg.get("port", "22")
    results.append(R(
        id="S22", category="ssh", title="SSH running on non-default port",
        severity=Severity.LOW if port == "22" else Severity.PASS,
        passed=port != "22",
        detail=f"Port = {port}. Moving off port 22 reduces log noise from automated scanners.",
        fix="Set 'Port <nonstandard>' in /etc/ssh/sshd_config (defense-in-depth, not a substitute for auth hardening)"
    ))

    # authorized key file location
    akf = cfg.get("authorizedkeysfile", ".ssh/authorized_keys")
    risky = "%" in akf or "//" in akf
    results.append(R(
        id="S23", category="ssh", title="AuthorizedKeysFile not using group-writable path",
        severity=Severity.MEDIUM if risky else Severity.PASS,
        passed=not risky,
        detail=f"AuthorizedKeysFile = {akf}",
        fix="Set 'AuthorizedKeysFile .ssh/authorized_keys' to prevent path traversal"
    ))

    return results


def check_users() -> list[R]:
    results: list[R] = []

    # UID 0 non-root
    uid0 = [e.pw_name for e in pwd.getpwall() if e.pw_uid == 0 and e.pw_name != "root"]
    results.append(R(
        id="U01", category="users", title="Only root has UID 0",
        severity=Severity.CRITICAL if uid0 else Severity.PASS,
        passed=not uid0,
        detail=f"Unauthorized UID 0 accounts: {uid0}" if uid0 else "Only root holds UID 0.",
        fix="awk -F: '($3==0 && $1!=\"root\") {print}' /etc/passwd — then remove or reassign"
    ))

    entries = shadow_entries()

    # empty passwords
    empty = [e["name"] for e in entries if e["hash"] == ""]
    results.append(R(
        id="U02", category="users", title="No accounts with empty passwords",
        severity=Severity.CRITICAL if empty else Severity.PASS,
        passed=not empty,
        detail=f"Empty-password accounts: {empty}" if empty else "No empty password hashes found.",
        fix="passwd <user>  or  passwd -l <user>  to lock"
    ))

    # weak hash algorithms (MD5 = $1$, old crypt = no $ prefix)
    weak_hash = [
        (e["name"], e["hash"][:4])
        for e in entries
        if e["hash"] not in ("!", "!!", "*", "x", "")
        and (e["hash"].startswith("$1$") or not e["hash"].startswith("$"))
    ]
    results.append(R(
        id="U03", category="users", title="No MD5/weak password hashes",
        severity=Severity.HIGH if weak_hash else Severity.PASS,
        passed=not weak_hash,
        detail=f"Accounts with weak hash: {weak_hash}" if weak_hash
               else "All active hashes use SHA-512 or yescrypt.",
        fix="Update /etc/pam.d/common-password to use yescrypt/sha512; force password resets"
    ))

    # root PATH safety
    root_path = os.environ.get("PATH", "")
    dangerous = [d for d in root_path.split(":") if d in (".", "", "..")]
    results.append(R(
        id="U04", category="users", title="Root PATH does not contain '.'",
        severity=Severity.HIGH if dangerous else Severity.PASS,
        passed=not dangerous,
        detail=f"PATH = {root_path}\nDangerous components: {dangerous}" if dangerous else f"PATH = {root_path}",
        fix="Remove '.' and empty entries from root's PATH in /root/.bashrc /root/.profile /etc/environment"
    ))

    # accounts with login shells and no password expiry
    valid_shells: set[str] = set()
    shells_raw = read_file("/etc/shells")
    if shells_raw:
        valid_shells = {l.strip() for l in shells_raw.splitlines() if l.strip() and not l.startswith("#")}

    no_expiry = []
    for e in entries:
        if e["hash"] in ("!", "!!", "*"):
            continue
        expire = e["expire"].strip()
        if expire not in ("", "0", "99999"):
            continue
        try:
            pw_entry = pwd.getpwnam(e["name"])
            if pw_entry.pw_shell in valid_shells and e["name"] not in ("root", "sync", "halt", "shutdown"):
                no_expiry.append(e["name"])
        except KeyError:
            pass

    results.append(R(
        id="U05", category="users", title="Login accounts have password expiry",
        severity=Severity.INFO if no_expiry else Severity.PASS,
        passed=not no_expiry,
        detail=f"No expiry set for: {no_expiry}" if no_expiry else "All login accounts have expiry configured.",
        fix="chage -M 90 <user>  to set max password age per account"
    ))

    # /etc/login.defs policy
    for cid, key, op, threshold, sev, desc, fix_val in [
        ("U06", "PASS_MAX_DAYS", "<=", 90,  Severity.MEDIUM,
         "Max password age; reduces exposure window after credential compromise.", 90),
        ("U07", "PASS_MIN_DAYS", ">=", 7,   Severity.LOW,
         "Min days between password changes; prevents cycling back to old passwords.", 7),
        ("U08", "PASS_WARN_AGE", ">=", 7,   Severity.LOW,
         "Days warning before password expiry.", 7),
        ("U09", "LOGIN_RETRIES", "<=", 5,   Severity.MEDIUM,
         "Max failed login attempts before lockout.", 5),
        ("U10", "LOGIN_TIMEOUT", "<=", 60,  Severity.LOW,
         "Max seconds allowed for login.", 60),
    ]:
        raw = login_defs_get(key)
        try:
            val = int(raw)
            passed = (val <= threshold) if op == "<=" else (val >= threshold)
        except (TypeError, ValueError):
            passed = False
            val = None
        results.append(R(
            id=cid, category="users", title=f"{key} {op} {threshold}",
            severity=sev if not passed else Severity.PASS,
            passed=passed,
            detail=desc + f"\n           /etc/login.defs: {key} = {raw or '(not set)'}",
            fix=f"Set '{key} {fix_val}' in /etc/login.defs"
        ))

    # UMASK
    umask = login_defs_get("UMASK")
    passed = umask is not None and umask.strip() in {"027", "077"}
    results.append(R(
        id="U11", category="users", title="Default umask 027 or 077",
        severity=Severity.MEDIUM if not passed else Severity.PASS,
        passed=passed,
        detail=f"UMASK = {umask or '(unset, likely 022)'}. Permissive umask leaks new files to group/world.",
        fix="Set 'UMASK 027' in /etc/login.defs and /etc/profile /etc/bash.bashrc"
    ))

    # accounts with interactive shell that are system accounts (uid < 1000, not root)
    suspicious_sys = [
        e.pw_name for e in pwd.getpwall()
        if 0 < e.pw_uid < 1000 and e.pw_shell in valid_shells
        and e.pw_name not in {"sync", "games"}
    ]
    results.append(R(
        id="U12", category="users", title="System accounts have non-interactive shells",
        severity=Severity.MEDIUM if suspicious_sys else Severity.PASS,
        passed=not suspicious_sys,
        detail=f"System UIDs with login shells: {suspicious_sys}" if suspicious_sys
               else "All system accounts use /sbin/nologin or /bin/false.",
        fix="usermod -s /usr/sbin/nologin <user>  for each system account that shouldn't log in"
    ))

    return results


def check_filesystem() -> list[R]:
    results: list[R] = []

    # critical file permission checks
    perm_table = [
        # (id, path, expected_mode, expected_uid, expected_gid, severity)
        ("F01", "/etc/passwd",           0o644, 0,  0,  Severity.HIGH),
        ("F02", "/etc/shadow",           0o640, 0,  42, Severity.CRITICAL),  # GID 42 = shadow
        ("F03", "/etc/group",            0o644, 0,  0,  Severity.MEDIUM),
        ("F04", "/etc/gshadow",          0o640, 0,  42, Severity.HIGH),
        ("F05", "/etc/ssh/sshd_config",  0o600, 0,  0,  Severity.HIGH),
        ("F06", "/etc/sudoers",          0o440, 0,  0,  Severity.HIGH),
        ("F07", "/etc/crontab",          0o600, 0,  0,  Severity.MEDIUM),
        ("F08", "/etc/hosts",            0o644, 0,  0,  Severity.LOW),
        ("F09", "/etc/hosts.allow",      0o644, 0,  0,  Severity.LOW),
        ("F10", "/etc/hosts.deny",       0o644, 0,  0,  Severity.LOW),
        ("F11", "/etc/passwd-",          0o600, 0,  0,  Severity.LOW),
        ("F12", "/etc/shadow-",          0o600, 0,  0,  Severity.MEDIUM),
        ("F13", "/etc/group-",           0o600, 0,  0,  Severity.LOW),
        ("F14", "/etc/gshadow-",         0o600, 0,  0,  Severity.MEDIUM),
        ("F15", "/etc/issue",            0o644, 0,  0,  Severity.LOW),
        ("F16", "/etc/issue.net",        0o644, 0,  0,  Severity.LOW),
        ("F17", "/boot/grub/grub.cfg",   0o600, 0,  0,  Severity.MEDIUM),
        ("F18", "/etc/ssh/ssh_host_rsa_key",  0o600, 0, 0, Severity.CRITICAL),
        ("F19", "/etc/ssh/ssh_host_ed25519_key", 0o600, 0, 0, Severity.CRITICAL),
    ]

    for cid, path, exp_mode, exp_uid, exp_gid, sev in perm_table:
        if not Path(path).exists():
            results.append(R(
                id=cid, category="filesystem", title=f"{path} permissions",
                severity=Severity.INFO, passed=True,
                detail=f"{path}: not present (skip)"
            ))
            continue
        actual_mode  = file_mode(path)
        actual_owner = file_owner(path)
        if actual_mode is None or actual_owner is None:
            continue
        issues = []
        if actual_mode != exp_mode:
            issues.append(f"mode {oct(actual_mode)} (expected {oct(exp_mode)})")
        if actual_owner[0] != exp_uid:
            issues.append(f"UID {actual_owner[0]} (expected {exp_uid})")
        if exp_gid >= 0 and actual_owner[1] != exp_gid:
            issues.append(f"GID {actual_owner[1]} (expected {exp_gid})")
        passed = not issues
        results.append(R(
            id=cid, category="filesystem", title=f"{path} permissions",
            severity=sev if not passed else Severity.PASS,
            passed=passed,
            detail=f"{path}: {', '.join(issues)}" if issues else f"{path}: OK ({oct(actual_mode)})",
            fix=f"chmod {oct(exp_mode)[2:]} {path}; chown root {path}" if not passed else None
        ))

    # SUID/SGID binary audit
    rc, out, _ = run("find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null", timeout=90)
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/pkexec", "/usr/bin/at",
        "/usr/bin/crontab", "/usr/bin/wall", "/usr/bin/write", "/usr/bin/ssh-agent",
        "/usr/bin/fusermount", "/usr/bin/fusermount3",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/eject/dmcrypt-get-device",
        "/usr/lib/x86_64-linux-gnu/utempter/utempter",
        "/usr/sbin/unix_chkpwd", "/bin/su", "/bin/ping",
        "/bin/mount", "/bin/umount", "/sbin/unix_chkpwd",
    }
    if rc == 0 and out:
        suid_bins = [l.strip() for l in out.splitlines() if l.strip()]
        unexpected = [b for b in suid_bins if b not in known_suid]
        results.append(R(
            id="F20", category="filesystem", title="SUID/SGID binary audit",
            severity=Severity.HIGH if unexpected else Severity.PASS,
            passed=not unexpected,
            detail=(f"{len(suid_bins)} total SUID/SGID binaries.\n"
                    f"           UNEXPECTED: {unexpected}") if unexpected
                   else f"{len(suid_bins)} SUID/SGID binaries — all match known whitelist.",
            fix="chmod u-s <binary>  or  chmod g-s <binary>  for unexpected entries"
        ))

    # world-writable files outside noisy dirs
    rc, out, _ = run(
        r"find / -xdev -type f -perm -0002 2>/dev/null"
        r" | grep -Ev '^(/tmp|/dev|/proc|/sys|/run|/var/lib/lxcfs)'",
        timeout=90
    )
    ww = [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []
    results.append(R(
        id="F21", category="filesystem", title="No unexpected world-writable files",
        severity=Severity.HIGH if ww else Severity.PASS,
        passed=not ww,
        detail=f"World-writable files ({len(ww)}): {ww[:20]}" + (" [truncated]" if len(ww) > 20 else "") if ww
               else "No unexpected world-writable files.",
        fix="chmod o-w <file>  for each result"
    ))

    # world-writable dirs missing sticky bit
    rc, out, _ = run(
        r"find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null"
        r" | grep -Ev '^(/proc|/sys|/dev)'",
        timeout=90
    )
    wwd = [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []
    results.append(R(
        id="F22", category="filesystem", title="World-writable dirs have sticky bit",
        severity=Severity.HIGH if wwd else Severity.PASS,
        passed=not wwd,
        detail=f"Directories missing sticky bit: {wwd}" if wwd else "All world-writable dirs have sticky bit.",
        fix="chmod +t <dir>  for each result"
    ))

    # unowned files
    rc, out, _ = run(
        r"find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -100",
        timeout=90
    )
    unowned = [l.strip() for l in out.splitlines() if l.strip()] if rc == 0 else []
    results.append(R(
        id="F23", category="filesystem", title="No unowned files",
        severity=Severity.MEDIUM if unowned else Severity.PASS,
        passed=not unowned,
        detail=f"Unowned files (first 100): {unowned}" if unowned else "No unowned files.",
        fix="chown root:root <file>  or delete; these may indicate leftover account artifacts"
    ))

    # /tmp mount options
    mounts = read_file("/proc/mounts") or ""
    tmp_line = next((l for l in mounts.splitlines() if re.match(r"\S+\s+/tmp\s", l)), None)
    if tmp_line:
        opts = tmp_line.split()[3]
        for opt in ("noexec", "nosuid", "nodev"):
            passed = opt in opts
            results.append(R(
                id=f"F24_{opt}", category="filesystem", title=f"/tmp mount: {opt}",
                severity=Severity.MEDIUM if not passed else Severity.PASS,
                passed=passed,
                detail=f"/tmp mount options: {opts}",
                fix=f"Add {opt} to /tmp entry in /etc/fstab; mount -o remount,{opt} /tmp"
            ))
    else:
        results.append(R(
            id="F24", category="filesystem", title="/tmp is a separate mount",
            severity=Severity.INFO, passed=False,
            detail="/tmp is not a distinct mount point; consider tmpfs with nodev,nosuid,noexec.",
            fix="Add to /etc/fstab: tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0"
        ))

    # /dev/shm
    shm_line = next((l for l in mounts.splitlines() if re.match(r"\S+\s+/dev/shm\s", l)), None)
    if shm_line:
        opts = shm_line.split()[3]
        for opt in ("noexec", "nosuid", "nodev"):
            passed = opt in opts
            results.append(R(
                id=f"F25_{opt}", category="filesystem", title=f"/dev/shm mount: {opt}",
                severity=Severity.MEDIUM if not passed else Severity.PASS,
                passed=passed,
                detail=f"/dev/shm options: {opts}",
                fix=f"Add {opt} to /dev/shm in /etc/fstab; mount -o remount,{opt} /dev/shm"
            ))

    # /home nodev
    home_line = next((l for l in mounts.splitlines() if re.match(r"\S+\s+/home\s", l)), None)
    if home_line:
        opts = home_line.split()[3]
        passed = "nodev" in opts
        results.append(R(
            id="F26", category="filesystem", title="/home mounted nodev",
            severity=Severity.LOW if not passed else Severity.PASS,
            passed=passed,
            detail=f"/home mount options: {opts}",
            fix="Add nodev to /home in /etc/fstab"
        ))

    return results


def check_services() -> list[R]:
    results: list[R] = []

    dangerous_svcs = {
        "telnet":      (Severity.CRITICAL, "Cleartext protocol; replace entirely with SSH."),
        "rsh":         (Severity.CRITICAL, "Cleartext + trust-based auth; abolished since 1990s."),
        "rlogin":      (Severity.CRITICAL, "Cleartext remote login; no place on a modern host."),
        "rexec":       (Severity.CRITICAL, "Transmits credentials in cleartext."),
        "ftp":         (Severity.HIGH,     "Cleartext FTP; use SFTP or FTPS."),
        "vsftpd":      (Severity.MEDIUM,   "Verify TLS is enforced if vsftpd is intentional."),
        "tftp":        (Severity.HIGH,     "TFTP has no authentication mechanism."),
        "cups":        (Severity.MEDIUM,   "Printing daemon; typically unnecessary on servers."),
        "avahi-daemon":(Severity.LOW,      "mDNS/Bonjour auto-discovery; not appropriate on servers."),
        "bluetooth":   (Severity.LOW,      "Bluetooth stack; disable on headless/server hosts."),
        "rpcbind":     (Severity.MEDIUM,   "Exposes NFS/NIS; disable if not needed."),
        "nfs-server":  (Severity.MEDIUM,   "NFS exports filesystem; verify exports and restrict."),
        "nis":         (Severity.HIGH,     "NIS/YP is an obsolete and insecure directory service."),
        "yp-tools":    (Severity.HIGH,     "NIS client tools; should not be present."),
        "snmpd":       (Severity.MEDIUM,   "SNMP v1/v2 use community strings as plaintext passwords."),
        "inetd":       (Severity.HIGH,     "Super-daemon that may enable legacy insecure services."),
        "xinetd":      (Severity.HIGH,     "Super-daemon that may enable legacy insecure services."),
        "finger":      (Severity.MEDIUM,   "Leaks username/last-login info to remote callers."),
        "talk":        (Severity.MEDIUM,   "Obsolete cleartext messaging daemon."),
        "chargen":     (Severity.HIGH,     "Character generator — used in DoS amplification attacks."),
        "discard":     (Severity.HIGH,     "Discard service — not needed on modern hosts."),
        "echo":        (Severity.HIGH,     "Echo service — used in DoS amplification attacks."),
        "daytime":     (Severity.MEDIUM,   "Leaks system time without auth."),
    }

    for svc, (sev, detail) in dangerous_svcs.items():
        if active_service(svc):
            results.append(R(
                id=f"SVC_{svc.upper()[:8].replace('-', '_')}",
                category="services", title=f"Dangerous service active: {svc}",
                severity=sev, passed=False, detail=detail,
                fix=f"systemctl disable --now {svc}"
            ))

    if not any(not r.passed for r in results):
        results.append(R(
            id="SVC_OK", category="services", title="No dangerous services detected",
            severity=Severity.PASS, passed=True,
            detail="None of the checked legacy/dangerous services are active."
        ))

    # listening sockets summary (informational)
    rc, out, _ = run("ss -tlnp 2>/dev/null")
    if rc == 0:
        open_all = [
            l.strip() for l in out.splitlines()[1:]
            if re.search(r"\s(0\.0\.0\.0|\*|::):", l)
        ]
        results.append(R(
            id="SVC_LISTEN", category="services",
            title="Services listening on all interfaces",
            severity=Severity.INFO, passed=True,
            detail=("Services bound to 0.0.0.0 or [::]:\n  " +
                    "\n  ".join(open_all[:30])) if open_all
                   else "No services found listening on all interfaces."
        ))

    return results


def check_firewall() -> list[R]:
    results: list[R] = []

    ufw_active       = False
    iptables_guarded = False
    nft_guarded      = False

    rc, out, _ = run("ufw status 2>/dev/null")
    ufw_active = rc == 0 and "active" in out.lower()

    rc, out_ipt, _ = run("iptables -L INPUT -n --line-numbers 2>/dev/null | head -5")
    iptables_guarded = rc == 0 and ("DROP" in out_ipt or "REJECT" in out_ipt)

    rc, out_nft, _ = run("nft list ruleset 2>/dev/null | wc -l")
    try:
        nft_guarded = rc == 0 and int(out_nft.strip()) > 10
    except ValueError:
        pass

    any_fw = ufw_active or iptables_guarded or nft_guarded
    results.append(R(
        id="FW01", category="firewall", title="A firewall is active",
        severity=Severity.CRITICAL if not any_fw else Severity.PASS,
        passed=any_fw,
        detail=(f"ufw: {'active' if ufw_active else 'inactive'} | "
                f"iptables DROP rules: {'yes' if iptables_guarded else 'no'} | "
                f"nftables rules: {'yes' if nft_guarded else 'no'}"),
        fix="systemctl enable --now ufw && ufw default deny incoming && ufw enable"
    ))

    if ufw_active:
        rc, out, _ = run("ufw status verbose 2>/dev/null")
        deny_in  = "deny (incoming)" in out.lower()
        deny_fwd = "deny (routed)" in out.lower() or "disabled (routed)" in out.lower()
        results.append(R(
            id="FW02", category="firewall", title="ufw default deny incoming",
            severity=Severity.HIGH if not deny_in else Severity.PASS,
            passed=deny_in,
            detail=f"ufw default incoming: {'deny' if deny_in else 'allow/other'}",
            fix="ufw default deny incoming"
        ))
        results.append(R(
            id="FW03", category="firewall", title="ufw default deny/disable routing",
            severity=Severity.MEDIUM if not deny_fwd else Severity.PASS,
            passed=deny_fwd,
            detail=f"ufw default routed: {'deny/disabled' if deny_fwd else 'allow'}",
            fix="ufw default deny routed"
        ))

    # iptables default policy check
    for table_id, chain in [("FW04", "INPUT"), ("FW05", "FORWARD")]:
        rc, out, _ = run(f"iptables -L {chain} -n 2>/dev/null | head -1")
        if rc == 0 and "policy" in out.lower():
            drop = "DROP" in out.upper()
            results.append(R(
                id=table_id, category="firewall", title=f"iptables {chain} default DROP",
                severity=Severity.HIGH if not drop else Severity.PASS,
                passed=drop,
                detail=f"iptables {chain}: {out}",
                fix=f"iptables -P {chain} DROP"
            ))

    # ip6tables
    rc, out, _ = run("ip6tables -L INPUT -n 2>/dev/null | head -1")
    if rc == 0 and "policy" in out.lower():
        drop6 = "DROP" in out.upper()
        results.append(R(
            id="FW06", category="firewall", title="ip6tables INPUT default DROP",
            severity=Severity.MEDIUM if not drop6 else Severity.PASS,
            passed=drop6,
            detail=f"ip6tables INPUT: {out}",
            fix="ip6tables -P INPUT DROP"
        ))

    return results


def check_pam() -> list[R]:
    results: list[R] = []

    pq = read_file("/etc/security/pwquality.conf") or ""
    common_pw = read_file("/etc/pam.d/common-password") or ""

    def pq_val(key: str) -> Optional[str]:
        m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", pq, re.MULTILINE)
        if m:
            return m.group(1)
        # fallback: check pam.d line args
        m2 = re.search(rf"{re.escape(key)}=(\S+)", common_pw)
        return m2.group(1) if m2 else None

    # minlen
    minlen = pq_val("minlen")
    try:
        passed = int(minlen) >= 12
    except (TypeError, ValueError):
        passed = False
    results.append(R(
        id="P01", category="pam", title="Password minlen >= 12",
        severity=Severity.HIGH if not passed else Severity.PASS,
        passed=passed,
        detail=f"pwquality minlen = {minlen or '(not set)'}",
        fix="Set 'minlen = 14' in /etc/security/pwquality.conf"
    ))

    # complexity credits (negative = require at least N of that class)
    for cid, opt, label in [
        ("P02", "dcredit", "digit"),
        ("P03", "ucredit", "uppercase"),
        ("P04", "lcredit", "lowercase"),
        ("P05", "ocredit", "special character"),
    ]:
        val = pq_val(opt)
        try:
            passed = int(val) < 0
        except (TypeError, ValueError):
            passed = False
        results.append(R(
            id=cid, category="pam", title=f"Password requires {label} ({opt})",
            severity=Severity.MEDIUM if not passed else Severity.PASS,
            passed=passed,
            detail=f"pwquality {opt} = {val or '(not set, no requirement)'}",
            fix=f"Set '{opt} = -1' in /etc/security/pwquality.conf"
        ))

    # retry
    retry = pq_val("retry")
    try:
        passed = int(retry) <= 3
    except (TypeError, ValueError):
        passed = False
    results.append(R(
        id="P06", category="pam", title="pwquality retry <= 3",
        severity=Severity.LOW if not passed else Severity.PASS,
        passed=passed,
        detail=f"pwquality retry = {retry or '(not set)'}",
        fix="Set 'retry = 3' in /etc/security/pwquality.conf"
    ))

    # pam_pwhistory
    rc, out, _ = run("grep -rh 'pam_pwhistory' /etc/pam.d/ 2>/dev/null | grep -v '^#'")
    pw_hist = rc == 0 and out.strip() != ""
    remember = None
    if pw_hist:
        m = re.search(r"remember=(\d+)", out)
        remember = int(m.group(1)) if m else None
    passed = pw_hist and (remember is None or remember >= 5)
    results.append(R(
        id="P07", category="pam", title="Password history enforced (pam_pwhistory remember >= 5)",
        severity=Severity.MEDIUM if not passed else Severity.PASS,
        passed=passed,
        detail=f"pam_pwhistory: {'configured' if pw_hist else 'NOT configured'}"
               + (f", remember={remember}" if remember is not None else ""),
        fix="Add to /etc/pam.d/common-password:\n"
            "           password required pam_pwhistory.so remember=5 use_authtok"
    ))

    # pam_faillock / pam_tally2
    rc, out, _ = run("grep -rh 'pam_faillock\\|pam_tally2' /etc/pam.d/ 2>/dev/null | grep -v '^#'")
    lockout = rc == 0 and out.strip() != ""
    deny = None
    if lockout:
        m = re.search(r"deny=(\d+)", out)
        deny = int(m.group(1)) if m else None
    passed = lockout and (deny is None or deny <= 5)
    results.append(R(
        id="P08", category="pam", title="Account lockout configured (pam_faillock deny <= 5)",
        severity=Severity.HIGH if not passed else Severity.PASS,
        passed=passed,
        detail=f"pam_faillock/tally2: {'configured' if lockout else 'NOT configured'}"
               + (f", deny={deny}" if deny is not None else ""),
        fix="Add to /etc/pam.d/common-auth:\n"
            "           auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n"
            "           auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900"
    ))

    # pam_wheel on su
    su_conf = read_file("/etc/pam.d/su") or ""
    wheel = "pam_wheel" in su_conf and not all(
        l.strip().startswith("#") for l in su_conf.splitlines() if "pam_wheel" in l
    )
    results.append(R(
        id="P09", category="pam", title="su access restricted via pam_wheel",
        severity=Severity.MEDIUM if not wheel else Severity.PASS,
        passed=wheel,
        detail="pam_wheel restricts su to members of the wheel/sudo group.",
        fix="Uncomment or add in /etc/pam.d/su:\n"
            "           auth required pam_wheel.so use_uid"
    ))

    # /etc/pam.d/login nullok check
    login_conf = read_file("/etc/pam.d/login") or ""
    nullok = "nullok" in login_conf.lower()
    results.append(R(
        id="P10", category="pam", title="nullok not set in /etc/pam.d/login",
        severity=Severity.HIGH if nullok else Severity.PASS,
        passed=not nullok,
        detail="nullok allows logins with empty passwords; must be removed.",
        fix="Remove 'nullok' from pam_unix lines in /etc/pam.d/login"
    ))

    return results


def check_sudo() -> list[R]:
    results: list[R] = []

    # visudo syntax
    rc, _, err = run("visudo -c 2>/dev/null")
    results.append(R(
        id="SU01", category="sudo", title="sudoers syntax valid",
        severity=Severity.CRITICAL if rc != 0 else Severity.PASS,
        passed=rc == 0,
        detail=f"visudo -c: {'OK' if rc == 0 else err}",
        fix="visudo  — fix syntax errors before anything else"
    ))

    # NOPASSWD entries
    rc, out, _ = run("grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
    nopw = [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
    results.append(R(
        id="SU02", category="sudo", title="No NOPASSWD sudo rules",
        severity=Severity.HIGH if nopw else Severity.PASS,
        passed=not nopw,
        detail=f"NOPASSWD entries: {nopw}" if nopw else "No NOPASSWD entries found.",
        fix="Remove NOPASSWD from: " + "; ".join(nopw) if nopw else None
    ))

    # overly broad command grants (ALL commands, not just user spec)
    rc, out, _ = run(
        r"grep -rh 'ALL\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
        r" | grep -v '^#' | grep -v '^%\?root\s' | grep -Ev '^\s*Defaults'",
    )
    broad = [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
    results.append(R(
        id="SU03", category="sudo", title="No overly broad sudo rules",
        severity=Severity.MEDIUM if broad else Severity.PASS,
        passed=not broad,
        detail=f"Broad sudo grants (ALL commands):\n  " + "\n  ".join(broad) if broad
               else "No unexpected wildcard sudo grants.",
        fix="Restrict sudo grants to specific command paths rather than ALL"
    ))

    # I/O logging
    rc, out, _ = run(
        r"grep -rh 'log_input\|log_output\|iolog_dir\|Defaults.*log' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"
    )
    logging_on = rc == 0 and out.strip() != ""
    results.append(R(
        id="SU04", category="sudo", title="sudo I/O logging configured",
        severity=Severity.LOW if not logging_on else Severity.PASS,
        passed=logging_on,
        detail="sudo I/O logging records commands and session output for audit.",
        fix="Add to /etc/sudoers:\n"
            "           Defaults log_input, log_output\n"
            "           Defaults iolog_dir=/var/log/sudo-io"
    ))

    # sudo version / CVE hint
    rc, out, _ = run("sudo --version 2>/dev/null | head -1")
    if rc == 0:
        results.append(R(
            id="SU05", category="sudo", title="sudo version (CVE awareness)",
            severity=Severity.INFO, passed=True,
            detail=f"{out}\nNotable CVEs: CVE-2021-3156 (Baron Samedit, heap overflow, < 1.9.5p2)",
            refs=["https://www.sudo.ws/security/advisories/baron_samedit/"]
        ))

    return results


def check_packages() -> list[R]:
    results: list[R] = []

    for cid, pkg, sev, desc, fix in [
        ("PKG01", "unattended-upgrades", Severity.HIGH,
         "Applies security updates automatically without manual intervention.",
         "apt-get install -y unattended-upgrades && dpkg-reconfigure unattended-upgrades"),
        ("PKG02", "apt-listchanges",     Severity.LOW,
         "Reports changelogs on upgrade; helps catch unexpected changes.",
         "apt-get install -y apt-listchanges"),
        ("PKG03", "debsums",             Severity.MEDIUM,
         "Verifies MD5 checksums of installed package files for file-integrity monitoring.",
         "apt-get install -y debsums"),
        ("PKG04", "rkhunter",            Severity.MEDIUM,
         "Scans for rootkits, backdoors, and known local exploits.",
         "apt-get install -y rkhunter && rkhunter --update && rkhunter --propupd"),
        ("PKG05", "auditd",              Severity.MEDIUM,
         "Kernel-level audit logging; required for CIS/STIG compliance.",
         "apt-get install -y auditd audispd-plugins"),
        ("PKG06", "fail2ban",            Severity.MEDIUM,
         "Bans IPs with repeated auth failures; reduces brute-force exposure.",
         "apt-get install -y fail2ban && systemctl enable --now fail2ban"),
        ("PKG07", "aide",                Severity.MEDIUM,
         "Advanced Intrusion Detection Environment — host-based file-integrity monitoring.",
         "apt-get install -y aide && aideinit"),
        ("PKG08", "apparmor",            Severity.HIGH,
         "Mandatory access control framework for Debian/Ubuntu.",
         "apt-get install -y apparmor apparmor-utils"),
    ]:
        installed = pkg_installed(pkg)
        results.append(R(
            id=cid, category="packages", title=f"{pkg} installed",
            severity=sev if not installed else Severity.PASS,
            passed=installed, detail=desc, fix=fix
        ))

    # unattended-upgrades enabled
    if pkg_installed("unattended-upgrades"):
        rc, _, _ = run("systemctl is-enabled unattended-upgrades 2>/dev/null")
        enabled = rc == 0
        results.append(R(
            id="PKG09", category="packages", title="unattended-upgrades service enabled",
            severity=Severity.HIGH if not enabled else Severity.PASS,
            passed=enabled,
            detail="The service must be enabled to apply updates automatically.",
            fix="systemctl enable unattended-upgrades"
        ))

    # pending security updates (uses apt-get -s to avoid modification)
    rc, out, _ = run("apt-get -s upgrade 2>/dev/null | grep -ci security", timeout=30)
    try:
        n = int(out.strip())
    except ValueError:
        n = 0
    results.append(R(
        id="PKG10", category="packages", title="No pending security updates",
        severity=Severity.HIGH if n > 0 else Severity.PASS,
        passed=n == 0,
        detail=f"{n} pending security package update(s) detected." if n > 0
               else "No pending security updates.",
        fix="apt-get update && apt-get upgrade -y"
    ))

    # compiler tools on server
    for tool in ("gcc", "cc", "g++"):
        path = shutil.which(tool)
        if path:
            results.append(R(
                id=f"PKG11_{tool}", category="packages", title=f"Compiler {tool} present",
                severity=Severity.LOW, passed=False,
                detail=f"{tool} found at {path}. Compilers on production servers enable post-exploit compilation.",
                fix=f"apt-get remove -y {tool}  or restrict access: chmod o-rx {path}"
            ))

    return results


def check_logging() -> list[R]:
    results: list[R] = []

    # syslog daemon
    syslog_active = active_service("rsyslog", "syslog", "syslog-ng")
    results.append(R(
        id="LOG01", category="logging", title="syslog daemon active",
        severity=Severity.HIGH if not syslog_active else Severity.PASS,
        passed=syslog_active,
        detail="rsyslog/syslog-ng must be running to capture system events.",
        fix="apt-get install -y rsyslog && systemctl enable --now rsyslog"
    ))

    # auditd
    auditd_active = active_service("auditd")
    results.append(R(
        id="LOG02", category="logging", title="auditd running",
        severity=Severity.MEDIUM if not auditd_active else Severity.PASS,
        passed=auditd_active,
        detail="auditd provides syscall-level audit trails required for forensics and compliance.",
        fix="systemctl enable --now auditd"
    ))

    if auditd_active:
        # audit rule coverage
        rc, out, _ = run("auditctl -l 2>/dev/null | grep -vc '^#'")
        try:
            rule_count = int(out.strip())
        except ValueError:
            rule_count = 0
        results.append(R(
            id="LOG03", category="logging", title="auditd has rule coverage",
            severity=Severity.LOW if rule_count < 10 else Severity.PASS,
            passed=rule_count >= 10,
            detail=f"Active audit rules: {rule_count}. "
                   "Recommend CIS or DISA STIG rule sets.",
            fix="Install rules: cp /usr/share/doc/auditd/examples/rules/*.rules /etc/audit/rules.d/"
        ))

        # check for critical audit rules
        rc, rules, _ = run("auditctl -l 2>/dev/null")
        critical_rules = {
            "privileged":   r"-a always,exit -F path=/usr/bin/sudo",
            "passwd_change":r"-w /etc/passwd -p wa",
            "shadow_change":r"-w /etc/shadow -p wa",
            "sudoers":      r"-w /etc/sudoers -p wa",
            "login_events": r"-w /var/log/faillog",
        }
        for key, pattern in critical_rules.items():
            present = re.search(re.escape(pattern.split()[0]) + r".*" + re.escape(pattern.split()[-1]),
                                rules, re.IGNORECASE) if rules else False
            results.append(R(
                id=f"LOG04_{key}", category="logging", title=f"Audit rule: {key}",
                severity=Severity.LOW if not present else Severity.PASS,
                passed=bool(present),
                detail=f"Expected audit rule pattern for {key} {'found' if present else 'NOT found'}.",
                fix=f"Add rule matching: {pattern}"
            ))

    # auth.log permissions
    for logfile in ("/var/log/auth.log", "/var/log/syslog", "/var/log/messages"):
        if not Path(logfile).exists():
            continue
        perms = file_mode(logfile)
        if perms:
            world_read = bool(perms & stat.S_IROTH)
            world_write= bool(perms & stat.S_IWOTH)
            ok = not world_read and not world_write
            results.append(R(
                id=f"LOG05_{logfile.split('/')[-1]}", category="logging",
                title=f"{logfile} not world-readable/writable",
                severity=Severity.MEDIUM if not ok else Severity.PASS,
                passed=ok,
                detail=f"{logfile}: {oct(perms)}",
                fix=f"chmod 640 {logfile}"
            ))

    # journald persistent storage
    jconf = read_file("/etc/systemd/journald.conf") or ""
    persistent = bool(re.search(r"^\s*Storage\s*=\s*persistent", jconf, re.MULTILINE))
    results.append(R(
        id="LOG06", category="logging", title="journald persistent storage",
        severity=Severity.LOW if not persistent else Severity.PASS,
        passed=persistent,
        detail="Persistent journald storage survives reboots; essential for incident response.",
        fix="Set 'Storage=persistent' in /etc/systemd/journald.conf; "
            "mkdir -p /var/log/journal; systemctl restart systemd-journald"
    ))

    return results


def check_apparmor() -> list[R]:
    results: list[R] = []

    active = active_service("apparmor")
    if not active:
        rc, out, _ = run("aa-status 2>/dev/null")
        active = rc == 0 and "profiles are loaded" in out

    results.append(R(
        id="AA01", category="apparmor", title="AppArmor active",
        severity=Severity.HIGH if not active else Severity.PASS,
        passed=active,
        detail="AppArmor provides mandatory access control to confine processes to minimum privilege.",
        fix="apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor"
    ))

    if active:
        rc, out, _ = run("aa-status 2>/dev/null")
        if rc == 0:
            m_loaded   = re.search(r"(\d+) profiles are loaded", out)
            m_enforce  = re.search(r"(\d+) profiles are in enforce mode", out)
            m_complain = re.search(r"(\d+) profiles are in complain mode", out)
            loaded   = int(m_loaded.group(1))   if m_loaded   else 0
            enforce  = int(m_enforce.group(1))  if m_enforce  else 0
            complain = int(m_complain.group(1)) if m_complain else 0

            results.append(R(
                id="AA02", category="apparmor", title="AppArmor enforce profile count",
                severity=Severity.INFO if enforce == 0 else Severity.PASS,
                passed=enforce > 0,
                detail=f"Loaded: {loaded} | Enforcing: {enforce} | Complain: {complain}",
                fix="aa-enforce /etc/apparmor.d/*  to switch all profiles to enforce mode"
            ))

            if complain > 0:
                results.append(R(
                    id="AA03", category="apparmor", title="AppArmor profiles not in complain mode",
                    severity=Severity.LOW, passed=False,
                    detail=f"{complain} profile(s) in complain mode — not enforcing.",
                    fix="Review and enforce: aa-enforce /etc/apparmor.d/<profile>"
                ))

    return results


def check_misc() -> list[R]:
    results: list[R] = []

    # core dumps disabled in limits.conf
    rc, out, _ = run("grep -rh 'core' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
    core_off = rc == 0 and re.search(r"(hard|soft)\s+core\s+0", out) is not None
    results.append(R(
        id="M01", category="misc", title="Core dumps disabled in limits.conf",
        severity=Severity.MEDIUM if not core_off else Severity.PASS,
        passed=core_off,
        detail="Core dumps can expose memory contents including credentials.",
        fix="Add to /etc/security/limits.conf:\n"
            "           * hard core 0\n"
            "           * soft core 0"
    ))

    # systemd core dump storage
    coredump_conf = read_file("/etc/systemd/coredump.conf") or ""
    sd_core_off = bool(re.search(r"^\s*Storage\s*=\s*none", coredump_conf, re.MULTILINE))
    results.append(R(
        id="M02", category="misc", title="systemd coredump storage=none",
        severity=Severity.MEDIUM if not sd_core_off else Severity.PASS,
        passed=sd_core_off,
        detail="Systemd coredump can capture sensitive process memory.",
        fix="Set 'Storage=none' and 'ProcessSizeMax=0' in /etc/systemd/coredump.conf"
    ))

    # Ctrl+Alt+Delete masked
    rc, out, _ = run("systemctl status ctrl-alt-del.target 2>/dev/null")
    masked = "masked" in out.lower()
    results.append(R(
        id="M03", category="misc", title="Ctrl+Alt+Delete reboot masked",
        severity=Severity.MEDIUM if not masked else Severity.PASS,
        passed=masked,
        detail="Unmasked ctrl-alt-del allows local users to trigger a reboot via keyboard.",
        fix="systemctl mask ctrl-alt-del.target && systemctl daemon-reload"
    ))

    # NTP
    ntp_ok = False
    for svc in ("chronyd", "chrony", "ntp", "timesyncd", "systemd-timesyncd"):
        if active_service(svc):
            ntp_ok = True
            break
    if not ntp_ok:
        rc, out, _ = run("timedatectl 2>/dev/null")
        ntp_ok = rc == 0 and "synchronized: yes" in out.lower()
    results.append(R(
        id="M04", category="misc", title="NTP/time synchronization active",
        severity=Severity.MEDIUM if not ntp_ok else Severity.PASS,
        passed=ntp_ok,
        detail="Accurate time is required for log correlation, Kerberos auth, and TLS certificate validation.",
        fix="systemctl enable --now systemd-timesyncd  OR  apt-get install -y chrony"
    ))

    # legal banner /etc/issue.net
    issue_net = (read_file("/etc/issue.net") or "").strip()
    meaningful_banner = len(issue_net) > 10 and any(
        w in issue_net.lower() for w in ("unauthorized", "authorized", "monitored", "warning")
    )
    results.append(R(
        id="M05", category="misc", title="Legal warning in /etc/issue.net",
        severity=Severity.LOW if not meaningful_banner else Severity.PASS,
        passed=meaningful_banner,
        detail=f"/etc/issue.net: {issue_net[:100] or '(empty)'}",
        fix="Populate /etc/issue.net with authorized-use-only notice"
    ))

    # GRUB password
    grub_cfg = read_file("/boot/grub/grub.cfg") or ""
    grub_pw = "password_pbkdf2" in grub_cfg
    results.append(R(
        id="M06", category="misc", title="GRUB bootloader password set",
        severity=Severity.MEDIUM if not grub_pw else Severity.PASS,
        passed=grub_pw,
        detail="Without a GRUB password, anyone with physical access can boot into recovery mode.",
        fix="grub-mkpasswd-pbkdf2 → paste hash into /etc/grub.d/40_custom → update-grub"
    ))

    # cron/at access control
    for deny_file in ("/etc/cron.allow", "/etc/at.allow"):
        exists = Path(deny_file).exists()
        opposite = deny_file.replace(".allow", ".deny")
        deny_exists = Path(opposite).exists()
        ok = exists or deny_exists
        results.append(R(
            id=f"M07_{deny_file.split('/')[-1]}", category="misc",
            title=f"cron/at access restricted ({deny_file.split('/')[-1]} or .deny)",
            severity=Severity.LOW if not ok else Severity.PASS,
            passed=ok,
            detail=f"{deny_file}: {'exists' if exists else 'missing'} | "
                   f"{opposite}: {'exists' if deny_exists else 'missing'}",
            fix=f"Create {deny_file} with explicit user list, or touch {opposite} to deny all"
        ))

    # cron directories not world-writable
    for cdir in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"):
        if not Path(cdir).exists():
            continue
        perms = file_mode(cdir)
        if perms and (perms & stat.S_IWOTH):
            results.append(R(
                id=f"M08_{cdir.split('/')[-1]}", category="misc",
                title=f"{cdir} not world-writable",
                severity=Severity.HIGH, passed=False,
                detail=f"{cdir} is world-writable ({oct(perms)}). Allows cron injection by any user.",
                fix=f"chmod o-w {cdir}"
            ))

    # MOTD info leakage
    motd = (read_file("/etc/motd") or "").strip()
    if motd and any(k in motd.lower() for k in ("linux", "ubuntu", "debian", "kernel", "version", "welcome to")):
        results.append(R(
            id="M09", category="misc", title="MOTD does not leak OS/version info",
            severity=Severity.LOW, passed=False,
            detail=f"/etc/motd: {motd[:120]}",
            fix="Remove OS version references from /etc/motd"
        ))

    # kernel module blacklist for uncommon/dangerous modules
    blacklist_conf = read_file("/etc/modprobe.d/sysaudit-blacklist.conf") or ""
    dangerous_mods = ["usb-storage", "dccp", "sctp", "rds", "tipc"]
    missing_blacklist = [m for m in dangerous_mods if m not in blacklist_conf]
    results.append(R(
        id="M10", category="misc", title="Dangerous kernel modules blacklisted",
        severity=Severity.MEDIUM if missing_blacklist else Severity.PASS,
        passed=not missing_blacklist,
        detail=f"Not blacklisted: {missing_blacklist}" if missing_blacklist
               else "All checked modules are blacklisted.",
        fix="Run --harden --category misc  or manually add entries to /etc/modprobe.d/blacklist.conf"
    ))

    # IPv6 informational
    rc, out, _ = run("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    ipv6_state = "disabled" if "= 1" in out else "enabled"
    results.append(R(
        id="M11", category="misc", title="IPv6 status (informational)",
        severity=Severity.INFO, passed=True,
        detail=f"IPv6 is {ipv6_state}. If unused, set net.ipv6.conf.all.disable_ipv6=1."
    ))

    # systemd-resolved DNS-over-TLS
    resolved_conf = read_file("/etc/systemd/resolved.conf") or ""
    dot_enabled = bool(re.search(r"^\s*DNSOverTLS\s*=\s*yes", resolved_conf, re.MULTILINE))
    results.append(R(
        id="M12", category="misc", title="DNS-over-TLS configured (systemd-resolved)",
        severity=Severity.LOW if not dot_enabled else Severity.PASS,
        passed=dot_enabled,
        detail="DNS-over-TLS prevents passive interception and manipulation of DNS queries.",
        fix="Set 'DNSOverTLS=yes' and 'DNS=9.9.9.9' in /etc/systemd/resolved.conf; "
            "systemctl restart systemd-resolved"
    ))

    return results


# ─── check registry ───────────────────────────────────────────────────────────

CHECKS: dict[str, Callable[[], list[R]]] = {
    "kernel":     check_kernel,
    "ssh":        check_ssh,
    "users":      check_users,
    "filesystem": check_filesystem,
    "services":   check_services,
    "firewall":   check_firewall,
    "pam":        check_pam,
    "sudo":       check_sudo,
    "packages":   check_packages,
    "logging":    check_logging,
    "apparmor":   check_apparmor,
    "misc":       check_misc,
}


# ─── hardening actions ────────────────────────────────────────────────────────

def harden_kernel(dry: bool = False) -> list[str]:
    targets = {
        "kernel.randomize_va_space":               "2",
        "kernel.dmesg_restrict":                   "1",
        "kernel.kptr_restrict":                    "2",
        "kernel.yama.ptrace_scope":                "1",
        "kernel.perf_event_paranoid":              "3",
        "kernel.unprivileged_bpf_disabled":        "1",
        "kernel.core_uses_pid":                    "1",
        "kernel.sysrq":                            "0",
        "kernel.panic":                            "60",
        "kernel.panic_on_oops":                    "1",
        "net.core.bpf_jit_harden":                 "2",
        "fs.suid_dumpable":                        "0",
        "fs.protected_hardlinks":                  "1",
        "fs.protected_symlinks":                   "1",
        "fs.protected_fifos":                      "2",
        "fs.protected_regular":                    "2",
        "net.ipv4.ip_forward":                     "0",
        "net.ipv4.conf.all.send_redirects":        "0",
        "net.ipv4.conf.default.send_redirects":    "0",
        "net.ipv4.conf.all.accept_redirects":      "0",
        "net.ipv4.conf.default.accept_redirects":  "0",
        "net.ipv6.conf.all.accept_redirects":      "0",
        "net.ipv6.conf.default.accept_redirects":  "0",
        "net.ipv4.conf.all.accept_source_route":   "0",
        "net.ipv4.conf.default.accept_source_route":"0",
        "net.ipv6.conf.all.accept_source_route":   "0",
        "net.ipv4.conf.all.log_martians":          "1",
        "net.ipv4.conf.default.log_martians":      "1",
        "net.ipv4.icmp_echo_ignore_broadcasts":    "1",
        "net.ipv4.icmp_ignore_bogus_error_responses":"1",
        "net.ipv4.tcp_syncookies":                 "1",
        "net.ipv4.conf.all.rp_filter":             "1",
        "net.ipv4.conf.default.rp_filter":         "1",
        "net.ipv4.tcp_rfc1337":                    "1",
        "net.ipv4.tcp_timestamps":                 "0",
        "net.ipv4.conf.all.secure_redirects":      "0",
        "net.ipv6.conf.all.accept_ra":             "0",
        "net.ipv6.conf.default.accept_ra":         "0",
        "net.ipv6.conf.all.forwarding":            "0",
    }
    applied = []
    conf = "/etc/sysctl.d/99-sysaudit.conf"
    if not dry:
        backup(conf)
    for key, val in targets.items():
        cur = sysctl_get(key)
        if cur == val:
            continue
        applied.append(f"{key} = {val}  (was: {cur or 'N/A'})")
        if not dry:
            sysctl_set(key, val)
            sysctl_persist(key, val, conf)
    return applied


def harden_ssh(dry: bool = False) -> list[str]:
    path = "/etc/ssh/sshd_config"
    if not dry:
        backup(path)
    content = read_file(path) or ""
    changes = []

    settings = {
        "PermitRootLogin":         "no",
        "PasswordAuthentication":  "no",
        "PermitEmptyPasswords":    "no",
        "X11Forwarding":           "no",
        "MaxAuthTries":            "4",
        "LoginGraceTime":          "60",
        "AllowAgentForwarding":    "no",
        "AllowTcpForwarding":      "no",
        "PermitUserEnvironment":   "no",
        "IgnoreRhosts":            "yes",
        "HostbasedAuthentication": "no",
        "UsePAM":                  "yes",
        "StrictModes":             "yes",
        "Compression":             "no",
        "ClientAliveInterval":     "300",
        "ClientAliveCountMax":     "3",
        "LogLevel":                "VERBOSE",
        "GSSAPIAuthentication":    "no",
        "Ciphers":
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "MACs":
            "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
        "KexAlgorithms":
            "curve25519-sha256,curve25519-sha256@libssh.org,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
    }

    new_lines = []
    applied = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        key = stripped.split()[0]
        match = next((k for k in settings if k.lower() == key.lower()), None)
        if match:
            new_line = f"{match} {settings[match]}"
            new_lines.append(new_line)
            changes.append(new_line)
            applied.add(match)
        else:
            new_lines.append(line)

    for k, v in settings.items():
        if k not in applied:
            entry = f"{k} {v}"
            new_lines.append(entry)
            changes.append(entry + "  [appended]")

    if dry:
        return changes

    Path(path).write_text("\n".join(new_lines) + "\n")
    rc, _, err = run("sshd -t 2>/dev/null")
    if rc != 0:
        latest = sorted(BACKUP_DIR.glob("sshd_config.*.bak"))
        if latest:
            shutil.copy2(str(latest[-1]), path)
        return [f"ERROR: sshd config invalid: {err}. Backup restored."]
    run("systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null")
    return changes


def harden_kernel_modules(dry: bool = False) -> list[str]:
    conf = "/etc/modprobe.d/99-sysaudit-blacklist.conf"
    modules = [
        ("cramfs",       "Legacy filesystem; not needed on modern servers."),
        ("freevxfs",     "Legacy filesystem; not needed."),
        ("jffs2",        "JFFS2 flash filesystem; not needed on x86 servers."),
        ("hfs",          "Apple HFS; not needed on Linux servers."),
        ("hfsplus",      "Apple HFS+; not needed on Linux servers."),
        ("udf",          "UDF/DVD filesystem; not needed on headless servers."),
        ("usb-storage",  "USB mass storage; disable to prevent exfil/malware via USB."),
        ("dccp",         "Datagram Congestion Control Protocol; rarely used, has had CVEs."),
        ("sctp",         "Stream Control Transmission Protocol; rarely needed, attack surface."),
        ("rds",          "Reliable Datagram Sockets; rarely used, has had privilege-esc CVEs."),
        ("tipc",         "Transparent Inter-Process Communication; not needed in standard deployments."),
        ("n-hdlc",       "HDLC line discipline; not needed on servers."),
        ("ax25",         "Amateur radio AX.25; not needed on servers."),
        ("netrom",       "Amateur radio NET/ROM; not needed on servers."),
        ("x25",          "X.25 WAN protocol; not needed on servers."),
        ("rose",         "Amateur radio ROSE; not needed on servers."),
        ("decnet",       "DECnet; not needed on modern servers."),
        ("econet",       "Acorn Econet; not needed."),
        ("af_802154",    "IEEE 802.15.4 (IoT); not needed on servers."),
        ("ipx",          "IPX/SPX (Novell NetWare); not needed."),
        ("appletalk",    "AppleTalk; obsolete, not needed."),
        ("psnap",        "PSNAP; not needed."),
        ("p8023",        "IEEE 802.3; not needed."),
        ("p8022",        "IEEE 802.2; not needed."),
        ("can",          "Controller Area Network; not needed on servers."),
        ("atm",          "Asynchronous Transfer Mode; legacy, not needed."),
    ]
    if dry:
        return [m for m, _ in modules]

    backup(conf)
    lines = [f"# sysaudit module blacklist — {time.strftime('%Y-%m-%d %H:%M:%S')}", ""]
    for mod, reason in modules:
        lines += [f"# {reason}", f"install {mod} /bin/true", f"blacklist {mod}", ""]
    Path(conf).write_text("\n".join(lines))
    run("update-initramfs -u 2>/dev/null", timeout=120)
    return [m for m, _ in modules]


def harden_login_defs(dry: bool = False) -> list[str]:
    path = "/etc/login.defs"
    if not dry:
        backup(path)
    content = read_file(path) or ""
    targets = {
        "PASS_MAX_DAYS": "90",
        "PASS_MIN_DAYS": "7",
        "PASS_WARN_AGE": "14",
        "UMASK":         "027",
        "LOGIN_RETRIES": "5",
        "LOGIN_TIMEOUT": "60",
        "SHA_CRYPT_MIN_ROUNDS": "65536",
        "SHA_CRYPT_MAX_ROUNDS": "65536",
    }
    changes = []
    for key, val in targets.items():
        pat = re.compile(rf"^(\s*{re.escape(key)}\s+)\S+", re.MULTILINE)
        old = pat.search(content)
        if old:
            content = pat.sub(rf"\g<1>{val}", content)
        else:
            content += f"\n{key}\t{val}\n"
        changes.append(f"{key} = {val}")
    if not dry:
        Path(path).write_text(content)
    return changes


def harden_misc(dry: bool = False) -> list[str]:
    changes = []

    # mask ctrl-alt-del
    if not dry:
        run("systemctl mask ctrl-alt-del.target 2>/dev/null")
        run("systemctl daemon-reload 2>/dev/null")
    changes.append("systemctl mask ctrl-alt-del.target")

    # disable core dumps in limits.conf
    limits_path = "/etc/security/limits.conf"
    if not dry:
        backup(limits_path)
        content = read_file(limits_path) or ""
        if "* hard core" not in content:
            with open(limits_path, "a") as f:
                f.write("\n# sysaudit: disable core dumps\n* hard core 0\n* soft core 0\n")
    changes.append("* hard core 0  →  /etc/security/limits.conf")

    # systemd coredump
    coredump_path = "/etc/systemd/coredump.conf.d/sysaudit.conf"
    if not dry:
        Path(coredump_path).parent.mkdir(parents=True, exist_ok=True)
        Path(coredump_path).write_text("[Coredump]\nStorage=none\nProcessSizeMax=0\n")
    changes.append("Storage=none  →  /etc/systemd/coredump.conf.d/sysaudit.conf")

    # legal banner
    banner_path = "/etc/issue.net"
    banner_text = (
        "WARNING: This system is for authorized use only. All activity is monitored\n"
        "and logged. Unauthorized access is prohibited and will be prosecuted.\n"
        "By continuing, you consent to these terms.\n"
    )
    if not dry:
        backup(banner_path)
        Path(banner_path).write_text(banner_text)
    changes.append("/etc/issue.net populated with legal warning")

    return changes


HARDEN_MAP: dict[str, Callable[..., list[str]]] = {
    "kernel":  harden_kernel,
    "ssh":     harden_ssh,
    "users":   harden_login_defs,
    "misc":    harden_misc,
}


# ─── reporting ────────────────────────────────────────────────────────────────

def score_results(results: list[R]) -> tuple[int, dict]:
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH:     15,
        Severity.MEDIUM:    7,
        Severity.LOW:       2,
        Severity.INFO:      0,
        Severity.PASS:      0,
    }
    counts = {s: 0 for s in Severity}
    for r in results:
        if not r.passed:
            counts[r.severity] += 1
    penalty = sum(weights[s] * n for s, n in counts.items())
    return max(0, 100 - penalty), counts


def print_results(results: list[R], verbose: bool = False) -> None:
    by_cat: dict[str, list[R]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    for cat, items in by_cat.items():
        failing = [r for r in items if not r.passed]
        if not failing and not verbose:
            continue
        print(f"\n{clr(f'[ {cat.upper()} ]', C.BOLD, C.BLUE)}")
        print("─" * 68)
        for r in items:
            if r.passed and not verbose:
                continue
            sev_tag = clr(f"[{SEV_LABEL[r.severity]}]", SEV_COLOR[r.severity])
            title   = clr(r.title, C.BOLD) if not r.passed else r.title
            print(f"  {sev_tag} {r.id:<10} {title}")
            if r.detail:
                for line in r.detail.splitlines():
                    print(f"             {clr(line, C.DIM)}")
            if r.fix and not r.passed:
                for fline in r.fix.splitlines():
                    print(f"             {clr('FIX:', C.CYAN)} {fline}")
            if r.refs:
                print(f"             {clr('REF:', C.BLUE)} {', '.join(r.refs)}")


def print_summary(results: list[R]) -> None:
    score, counts = score_results(results)
    total  = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    color  = C.GREEN if score >= 80 else (C.YELLOW if score >= 50 else C.RED)

    print("\n" + clr("═" * 68, C.DIM))
    print(clr(" AUDIT SUMMARY", C.BOLD))
    print(clr("═" * 68, C.DIM))
    print(f"  Score   : {clr(f'{score}/100', C.BOLD, color)}")
    print(f"  Checks  : {total} total  |  {clr(str(passed), C.GREEN)} passed  |  {clr(str(failed), C.RED)} failed")
    print()
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts[sev]
        if n:
            print(f"  {clr(SEV_LABEL[sev], SEV_COLOR[sev])}  ×  {n}")
    print(clr("═" * 68, C.DIM))


def export_json(results: list[R], path: str) -> None:
    score, counts = score_results(results)
    out = {
        "tool":    "sysaudit",
        "version": TOOL_VERSION,
        "host":    socket.gethostname(),
        "ts":      int(time.time()),
        "kernel":  platform.release(),
        "score":   score,
        "counts":  {s.name: c for s, c in counts.items()},
        "results": [
            {
                "id":       r.id,
                "category": r.category,
                "title":    r.title,
                "severity": r.severity.name,
                "passed":   r.passed,
                "detail":   r.detail,
                "fix":      r.fix,
                "refs":     r.refs,
            }
            for r in results
        ],
    }
    Path(path).write_text(json.dumps(out, indent=2))
    print(clr(f"JSON report → {path}", C.CYAN))


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sysaudit",
        description="Debian/Ubuntu system security audit + hardening tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python3 sysaudit.py --audit\n"
            "  sudo python3 sysaudit.py --audit --verbose --json /tmp/report.json\n"
            "  sudo python3 sysaudit.py --audit --category ssh,kernel,firewall\n"
            "  sudo python3 sysaudit.py --harden --category kernel,ssh\n"
            "  sudo python3 sysaudit.py --harden --category all --dry-run\n"
            "  sudo python3 sysaudit.py --audit --harden --json /tmp/report.json\n"
            f"\ncategories: {', '.join(CHECKS)}"
        )
    )
    p.add_argument("--audit",    action="store_true", help="Run all audit checks (read-only)")
    p.add_argument("--harden",   action="store_true", help="Apply automated hardening fixes")
    p.add_argument("--category", default="all",
                   help="Comma-separated category list (default: all)")
    p.add_argument("--verbose",  action="store_true", help="Show passing checks")
    p.add_argument("--json",     metavar="FILE",      help="Write JSON report to FILE")
    p.add_argument("--dry-run",  action="store_true",
                   help="With --harden: show planned changes without applying them")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if os.geteuid() != 0:
        print(clr("Error: must run as root (sudo).", C.RED + C.BOLD), file=sys.stderr)
        sys.exit(1)

    if not args.audit and not args.harden:
        print(clr("Specify --audit and/or --harden. Run with -h for help.", C.YELLOW))
        sys.exit(1)

    if args.category == "all":
        categories = list(CHECKS.keys())
    else:
        categories = [c.strip() for c in args.category.split(",")]
        unknown = [c for c in categories if c not in CHECKS]
        if unknown:
            print(clr(f"Unknown categories: {unknown}", C.RED))
            print(f"Valid: {list(CHECKS.keys())}")
            sys.exit(1)

    print(clr(f"\nsysaudit {TOOL_VERSION}", C.BOLD) +
          clr(f"  |  {socket.gethostname()}  |  {time.strftime('%Y-%m-%d %H:%M:%S')}", C.DIM))
    print(clr(f"Kernel: {platform.release()}  |  {platform.version()[:72]}", C.DIM))

    all_results: list[R] = []

    if args.audit:
        print(clr(f"\nAudit — {len(categories)} category/categories", C.CYAN))
        print("─" * 68)
        for cat in categories:
            sys.stdout.write(f"  {cat:<14} ")
            sys.stdout.flush()
            try:
                res = CHECKS[cat]()
            except Exception as exc:
                print(clr(f"ERROR: {exc}", C.RED))
                continue
            failures = [r for r in res if not r.passed and r.severity not in (Severity.INFO, Severity.PASS)]
            crits    = sum(1 for r in failures if r.severity == Severity.CRITICAL)
            highs    = sum(1 for r in failures if r.severity == Severity.HIGH)
            if failures:
                tag = clr(f"{len(failures)} issue(s)", C.RED if (crits or highs) else C.YELLOW)
                crit_tag = f"  {clr(f'{crits} CRIT', C.RED + C.BOLD)}" if crits else ""
                print(tag + crit_tag)
            else:
                print(clr("OK", C.GREEN))
            all_results.extend(res)

        print_results(all_results, verbose=args.verbose)
        print_summary(all_results)

        if args.json:
            export_json(all_results, args.json)

    if args.harden:
        if args.dry_run:
            print(clr("\n[DRY RUN] No changes will be written.", C.YELLOW))

        print(clr("\nHardening", C.BOLD))
        print("─" * 68)

        for cat in categories:
            fn = HARDEN_MAP.get(cat)
            if not fn:
                continue
            print(clr(f"\n  {cat}", C.BOLD))
            try:
                changes = fn(dry=args.dry_run)
                for c in changes:
                    marker = clr("~", C.YELLOW) if args.dry_run else clr("✓", C.GREEN)
                    print(f"    {marker} {c}")
                if not changes:
                    print(clr("    nothing to change", C.DIM))
            except Exception as exc:
                print(clr(f"    ERROR: {exc}", C.RED))

        # kernel modules always offered as part of kernel hardening
        if "kernel" in categories and not args.dry_run:
            print(clr("\n  kernel modules blacklist", C.BOLD))
            mods = harden_kernel_modules(dry=False)
            print(f"    {clr('✓', C.GREEN)} blacklisted {len(mods)} modules → "
                  f"/etc/modprobe.d/99-sysaudit-blacklist.conf")
        elif "kernel" in categories and args.dry_run:
            mods = harden_kernel_modules(dry=True)
            print(f"\n  kernel modules: would blacklist {len(mods)} modules")

        if not args.dry_run:
            print(clr(f"\nBackups in: {BACKUP_DIR}", C.DIM))


if __name__ == "__main__":
    main()
