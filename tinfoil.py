#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tinfoil - your machine's attack surface, in one command.

Runs entirely offline. Reads local state, makes no network calls, and never
writes anything outside stdout. Secrets it finds are redacted before display.

    python3 tinfoil.py            # full report
    python3 tinfoil.py --demo     # sample report with synthetic data
    python3 tinfoil.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "0.1.0"

HOME = Path.home()
SYSTEM = platform.system()
IS_MAC = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"
SUPPORTED_SYSTEMS = ("Darwin", "Linux")

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
SEV_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

FAIL, WARN, PASS, SKIP = "fail", "warn", "pass", "skip"
STATUS_RANK = {FAIL: 0, WARN: 1, PASS: 2, SKIP: 3}

CATEGORIES = ["system", "network", "credentials", "browser"]
CATEGORY_LABELS = {
    "system": "SYSTEM",
    "network": "NETWORK",
    "credentials": "CREDENTIALS",
    "browser": "BROWSER",
}


# --------------------------------------------------------------------------
# terminal styling
# --------------------------------------------------------------------------

class Ink:
    """ANSI styling that degrades to plain text when colour is unavailable."""

    def __init__(self, enabled: bool = True):
        self.on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return "\x1b[%sm%s\x1b[0m" % (code, text) if self.on else text

    def fg(self, n: int, text: str) -> str:
        return self._wrap("38;5;%d" % n, text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold_fg(self, n: int, text: str) -> str:
        return self._wrap("1;38;5;%d" % n, text)


ink = Ink(False)

COLOR_CRIT, COLOR_HIGH, COLOR_MED, COLOR_LOW = 203, 215, 222, 111
COLOR_OK, COLOR_DIM, COLOR_ACCENT = 114, 244, 116

SEV_COLOR = {CRITICAL: COLOR_CRIT, HIGH: COLOR_HIGH, MEDIUM: COLOR_MED, LOW: COLOR_LOW}


def supports_color(force: str) -> bool:
    if force == "never":
        return False
    if force == "always":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=8):
    """Run a command. Returns (rc, stdout, stderr); never raises."""
    try:
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )
    except Exception:
        return 127, "", ""


def read_text(path, max_bytes=4_000_000):
    """Read a file's head as text, or None if unreadable."""
    try:
        with open(str(path), "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", "replace")
    except Exception:
        return None


def tail_text(path, max_bytes=4_000_000):
    """Read a file's tail as text, or None if unreadable."""
    try:
        p = Path(path)
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            return fh.read().decode("utf-8", "replace")
    except Exception:
        return None


def mode_of(path):
    try:
        return stat.S_IMODE(Path(path).lstat().st_mode)
    except Exception:
        return None


def tilde(path) -> str:
    try:
        return "~/" + str(Path(path).relative_to(HOME))
    except Exception:
        return str(path)


def redact(value, keep=4) -> str:
    """Mask a secret so the report is safe to screenshot."""
    v = str(value)
    if len(v) <= keep + 3:
        return "*" * len(v)
    return v[:keep] + "*" * min(10, len(v) - keep - 2) + v[-2:]


def plural(n, one, many=None) -> str:
    return one if n == 1 else (many or one + "s")


# --------------------------------------------------------------------------
# secret detection
# --------------------------------------------------------------------------

SECRET_RULES = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    ("AWS secret key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{20,}\b")),
    ("Twilio SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("private key material", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("exported secret", re.compile(
        r"(?i)\bexport\s+[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY)"
        r"[A-Z0-9_]*\s*=\s*[\"']?([^\s\"']{6,})")),
    ("inline basic auth", re.compile(r"(?i)\bcurl\b[^\n]{0,120}?\s(?:-u|--user)\s+(\S+:\S{3,})")),
    ("URL with password", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]{4,})@[^\s/]+")),
    ("mysql inline password", re.compile(r"(?i)\bmysql\b[^\n]{0,80}?\s-p(\S{3,})")),
]

# Values that look secret-ish but are noise.
SECRET_NOISE = re.compile(
    r"(?i)^(?:x{4,}|\*+|<[^>]+>|\$\{[^}]+\}|changeme|password|your[_-]?\w*|example|redacted|null|none|true|false)$"
)


def _token_from(match) -> str:
    if match.groups():
        for g in match.groups():
            if g:
                return g
    return match.group(0)


def scan_secrets(text, max_hits=6):
    """Return [(label, redacted_token)] for secret-looking values in `text`."""
    hits = []
    seen = set()
    for label, rx in SECRET_RULES:
        for m in rx.finditer(text):
            token = _token_from(m).strip()
            if not token or SECRET_NOISE.match(token):
                continue
            key = (label, token)
            if key in seen:
                continue
            seen.add(key)
            hits.append((label, redact(token)))
            if len(hits) >= max_hits:
                return hits
    return hits


ZSH_TS = re.compile(r"^: \d{9,}:\d+;")


def scan_history_lines(lines, max_hits=5):
    """Scan shell-history lines; returns (hits, total_matching_lines)."""
    hits = []
    total = 0
    seen = set()
    for raw in lines:
        line = ZSH_TS.sub("", raw).strip()
        if not line or line.startswith("#"):
            continue
        found = scan_secrets(line, max_hits=1)
        if not found:
            continue
        total += 1
        label, token = found[0]
        if label in seen and len(hits) >= 3:
            continue
        seen.add(label)
        if len(hits) < max_hits:
            cmd = line.split()[0][:24] if line.split() else "?"
            hits.append((label, token, cmd))
    return hits, total


# --------------------------------------------------------------------------
# check registry
# --------------------------------------------------------------------------

@dataclass
class Result:
    status: str
    summary: str = ""
    details: list = field(default_factory=list)
    fix: list = field(default_factory=list)


@dataclass
class Check:
    id: str
    title: str
    category: str
    severity: str
    weight: int
    platforms: tuple
    deep: bool
    func: object


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    weight: int
    status: str
    summary: str
    details: list
    fix: list
    ms: int = 0


CHECKS = []


def check(cid, title, category, severity=MEDIUM, weight=5,
          platforms=("Darwin", "Linux"), deep=False):
    def decorator(fn):
        CHECKS.append(Check(cid, title, category, severity, weight,
                            tuple(platforms), deep, fn))
        return fn
    return decorator


# ==========================================================================
# SYSTEM
# ==========================================================================

@check("disk-encryption", "Full-disk encryption", "system", CRITICAL, 12)
def chk_disk_encryption():
    if IS_MAC:
        rc, out, err = run(["fdesetup", "status"])
        blob = (out + err).lower()
        if "filevault is on" in blob:
            return Result(PASS, "FileVault is on")
        if "filevault is off" in blob:
            return Result(
                FAIL,
                "FileVault is OFF - anyone holding this disk reads every file on it",
                fix=["sudo fdesetup enable"],
            )
        return Result(SKIP, "could not determine FileVault state")

    rc, out, _ = run(["lsblk", "-o", "NAME,TYPE,MOUNTPOINT", "-n"])
    if rc == 0 and out.strip():
        if re.search(r"\bcrypt\b", out):
            return Result(PASS, "dm-crypt/LUKS volume is in use")
        return Result(
            FAIL,
            "no encrypted block device found - the filesystem looks unencrypted",
            fix=["# LUKS must be set up at install time; see `man cryptsetup`"],
        )
    crypttab = read_text("/etc/crypttab") or ""
    if [ln for ln in crypttab.splitlines() if ln.strip() and not ln.startswith("#")]:
        return Result(PASS, "/etc/crypttab declares encrypted volumes")
    return Result(SKIP, "could not determine disk encryption state")


@check("firewall", "Host firewall", "system", HIGH, 8)
def chk_firewall():
    if IS_MAC:
        sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        if Path(sfw).exists():
            rc, out, err = run([sfw, "--getglobalstate"])
            blob = (out + err).lower()
            if "state is 1" in blob or "enabled" in blob:
                details, fix = [], []
                _, so, se = run([sfw, "--getstealthmode"])
                if "disabled" in (so + se).lower():
                    details.append("stealth mode off - the Mac answers probes from any network")
                    fix.append("sudo %s --setstealthmode on" % sfw)
                return Result(WARN if details else PASS,
                              "application firewall is enabled", details, fix)
            if "state is 0" in blob or "disabled" in blob:
                return Result(FAIL, "application firewall is disabled",
                              fix=["sudo %s --setglobalstate on" % sfw])
        rc, out, _ = run(["defaults", "read",
                          "/Library/Preferences/com.apple.alf", "globalstate"])
        if rc == 0 and out.strip().isdigit():
            return (Result(PASS, "application firewall is enabled")
                    if int(out.strip()) > 0 else
                    Result(FAIL, "application firewall is disabled",
                           fix=["sudo %s --setglobalstate on" % sfw]))
        return Result(SKIP, "could not read firewall state")

    rc, out, err = run(["firewall-cmd", "--state"])
    if rc == 0 and "running" in out:
        return Result(PASS, "firewalld is running")
    ufw_conf = read_text("/etc/ufw/ufw.conf") or ""
    if "ENABLED=yes" in ufw_conf:
        return Result(PASS, "ufw is enabled")
    if "ENABLED=no" in ufw_conf:
        return Result(FAIL, "ufw is installed but disabled", fix=["sudo ufw enable"])
    rc, out, _ = run(["nft", "list", "ruleset"])
    if rc == 0 and "chain input" in out.lower():
        return Result(PASS, "nftables ruleset is loaded")
    rc, out, _ = run(["iptables", "-S"])
    if rc == 0 and out.strip():
        if re.search(r"^-P INPUT (DROP|REJECT)", out, re.M):
            return Result(PASS, "iptables INPUT policy is restrictive")
        if len([ln for ln in out.splitlines() if ln.startswith("-A")]) > 0:
            return Result(WARN, "iptables rules exist but INPUT policy is ACCEPT",
                          fix=["sudo iptables -P INPUT DROP  # after allowing what you need"])
        return Result(FAIL, "no firewall rules are loaded", fix=["sudo ufw enable"])
    return Result(SKIP, "firewall rules need root to inspect")


@check("screen-lock", "Screen lock on wake", "system", MEDIUM, 6)
def chk_screen_lock():
    if IS_MAC:
        rc, out, err = run(["sysadminctl", "-screenLock", "status"])
        blob = (out + err).lower()
        if "screenlock" in blob:
            if re.search(r"screenlock (?:is )?off", blob):
                return Result(FAIL, "screen lock is off - waking the Mac needs no password",
                              fix=["# System Settings > Lock Screen > Require password"])
            if "immediate" in blob:
                return Result(PASS, "password required immediately on wake")
            m = re.search(r"delay (?:is|of) (\d+) seconds", blob)
            if m:
                secs = int(m.group(1))
                if secs > 300:
                    return Result(
                        WARN,
                        "screen lock only kicks in %d minutes after the display sleeps" % (secs // 60),
                        details=["until then, opening the lid gives full access with no password"],
                        fix=["# System Settings > Lock Screen > Require password after ... > Immediately"])
                return Result(PASS, "password required %d seconds after sleep" % secs)
        rc, out, _ = run(["defaults", "read", "com.apple.screensaver", "askForPassword"])
        if rc == 0 and out.strip().isdigit():
            if int(out.strip()) == 0:
                return Result(FAIL, "screensaver does not ask for a password",
                              fix=["defaults write com.apple.screensaver askForPassword -int 1"])
            return Result(PASS, "password required on wake")
        return Result(SKIP, "could not read screen-lock policy")

    rc, out, _ = run(["gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"])
    if rc == 0 and out.strip():
        if "true" in out.lower():
            return Result(PASS, "screen lock is enabled")
        return Result(FAIL, "GNOME screen lock is disabled",
                      fix=["gsettings set org.gnome.desktop.screensaver lock-enabled true"])
    return Result(SKIP, "no supported screen-lock backend found")


@check("auto-login", "Automatic login", "system", HIGH, 6, platforms=("Darwin",))
def chk_auto_login():
    rc, out, _ = run(["defaults", "read",
                      "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if rc == 0 and out.strip():
        return Result(FAIL,
                      "automatic login is on for '%s' - booting the Mac unlocks it" % out.strip(),
                      fix=["sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"])
    return Result(PASS, "automatic login is off")


@check("sip", "System Integrity Protection", "system", HIGH, 8, platforms=("Darwin",))
def chk_sip():
    rc, out, err = run(["csrutil", "status"])
    blob = (out + err).lower()
    if "enabled" in blob:
        return Result(PASS, "SIP is enabled")
    if "disabled" in blob:
        return Result(FAIL, "SIP is disabled - system files are writable by anything with root",
                      fix=["# Reboot into Recovery, then: csrutil enable"])
    return Result(SKIP, "could not read SIP status")


@check("gatekeeper", "Gatekeeper", "system", HIGH, 7, platforms=("Darwin",))
def chk_gatekeeper():
    rc, out, err = run(["spctl", "--status"])
    blob = (out + err).lower()
    if "assessments enabled" in blob:
        return Result(PASS, "Gatekeeper is enforcing")
    if "assessments disabled" in blob:
        return Result(FAIL, "Gatekeeper is off - unsigned apps launch without any check",
                      fix=["sudo spctl --master-enable"])
    return Result(SKIP, "could not read Gatekeeper status")


@check("quarantine", "Download quarantine", "system", MEDIUM, 5, platforms=("Darwin",))
def chk_quarantine():
    rc, out, _ = run(["defaults", "read", "com.apple.LaunchServices", "LSQuarantine"])
    val = out.strip().lower()
    if rc == 0 and val in ("0", "false", "no"):
        return Result(FAIL, "download quarantine is disabled - files from the internet skip Gatekeeper",
                      fix=["defaults delete com.apple.LaunchServices LSQuarantine"])
    return Result(PASS, "downloads are quarantined")


@check("pending-updates", "Pending OS updates", "system", HIGH, 7, platforms=("Darwin",))
def chk_pending_updates():
    rc, out, err = run(["softwareupdate", "--list", "--no-scan"], timeout=12)
    blob = out + err
    if "No new software available" in blob:
        return Result(PASS, "no pending updates in the cached catalog")
    labels = re.findall(r"^\s*\*\s*Label:\s*(.+)$", blob, re.M)
    if labels:
        sev = [l for l in labels if re.search(r"(?i)security|safari|xprotect|mrt", l)]
        return Result(
            FAIL if sev else WARN,
            "%d pending %s%s" % (len(labels), plural(len(labels), "update"),
                                 " (%d security-related)" % len(sev) if sev else ""),
            details=[l.strip() for l in labels[:6]],
            fix=["softwareupdate --install --all --restart"],
        )
    return Result(SKIP, "update catalog is not cached yet; run `softwareupdate --list` once")


@check("stale-uptime", "Time since last reboot", "system", LOW, 3)
def chk_stale_uptime():
    boot = None
    if IS_MAC:
        rc, out, _ = run(["sysctl", "-n", "kern.boottime"])
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            boot = int(m.group(1))
    else:
        raw = read_text("/proc/uptime")
        if raw:
            try:
                boot = int(time.time() - float(raw.split()[0]))
            except Exception:
                boot = None
    if boot is None:
        return Result(SKIP, "could not determine boot time")
    days = int((time.time() - boot) / 86400)
    if days >= 120:
        return Result(FAIL, "up for %d days - kernel patches almost certainly unapplied" % days,
                      fix=["sudo shutdown -r now"])
    if days >= 45:
        return Result(WARN, "up for %d days - pending kernel updates are not active yet" % days)
    return Result(PASS, "rebooted %d %s ago" % (days, plural(days, "day")))


@check("path-hygiene", "$PATH integrity", "system", HIGH, 7)
def chk_path_hygiene():
    entries = os.environ.get("PATH", "").split(os.pathsep)
    bad, soft, fix = [], [], []
    for raw in entries:
        if raw == "" or raw == ".":
            bad.append("%s - the current directory is on $PATH; any repo you cd into can hijack commands"
                       % ("(empty entry)" if raw == "" else "."))
            continue
        if not raw.startswith("/"):
            bad.append("%s - relative $PATH entry" % raw)
            continue
        try:
            st = Path(raw).stat()
        except OSError:
            continue
        m = stat.S_IMODE(st.st_mode)
        if m & stat.S_ISVTX:
            continue
        if m & 0o002:
            bad.append("%s is world-writable (%04o) - any local account can replace a "
                       "command you run" % (tilde(raw), m))
            fix.append("chmod o-w %s" % raw)
        elif m & 0o020 and st.st_uid != os.getuid():
            bad.append("%s is group-writable (%04o) and owned by uid %d - not by you"
                       % (tilde(raw), m, st.st_uid))
            fix.append("chmod g-w %s" % raw)
        elif m & 0o020:
            # The Homebrew layout: you own it, the admin group can write it. Worth
            # knowing, but "chmod g-w" here breaks `brew` - so no fix command.
            soft.append("%s is group-writable (%04o) - any other admin user on this Mac "
                        "could replace a command you run" % (tilde(raw), m))
    if bad:
        return Result(FAIL, "%d unsafe $PATH %s" % (len(bad), plural(len(bad), "entry", "entries")),
                      bad + soft, fix)
    if soft:
        return Result(WARN, "%d $PATH %s writable by the admin group"
                      % (len(soft), plural(len(soft), "entry", "entries")),
                      soft,
                      fix=["# expected if you use Homebrew; it matters only when other "
                           "people have admin accounts here"])
    return Result(PASS, "all %d $PATH entries are owned and write-protected" % len(entries))


@check("sudo-nopasswd", "Passwordless sudo", "system", HIGH, 7)
def chk_sudo_nopasswd():
    rc, out, err = run(["sudo", "-n", "-l"], timeout=6)
    if rc != 0:
        return Result(SKIP, "sudo rules need a password to list (that itself is a good sign)")
    lines = [ln.strip() for ln in out.splitlines() if "NOPASSWD" in ln]
    if lines:
        blanket = [ln for ln in lines if re.search(r"NOPASSWD:\s*ALL\s*$", ln)]
        return Result(
            FAIL if blanket else WARN,
            "sudo runs without a password%s" % (" for ALL commands" if blanket else ""),
            details=[ln[:110] for ln in lines[:5]],
            fix=["sudo visudo  # remove the NOPASSWD tag"],
        )
    return Result(PASS, "sudo always requires a password")


# ==========================================================================
# NETWORK
# ==========================================================================

LOOPBACK = {"127.0.0.1", "::1", "[::1]", "localhost"}
WILDCARD = {"*", "0.0.0.0", "::", "[::]", "[*]"}

# Ports that should essentially never face a network.
DANGEROUS_PORTS = {
    23: "telnet (credentials in cleartext)",
    445: "SMB file sharing",
    1433: "MSSQL database",
    2375: "Docker API, unauthenticated - equals root on this host",
    2376: "Docker API over TLS",
    3306: "MySQL database",
    3283: "Apple Remote Desktop (remote control)",
    3389: "RDP",
    5432: "PostgreSQL database",
    5900: "VNC / Screen Sharing",
    6379: "Redis - usually unauthenticated by default",
    8020: "Hadoop",
    9200: "Elasticsearch - usually unauthenticated by default",
    11211: "memcached - unauthenticated, amplification vector",
    27017: "MongoDB database",
}

# Listeners macOS opens on its own. Still worth seeing, but they are not a
# misconfiguration you introduced, so they do not fail the check on their own.
EXPECTED_SERVICES = {
    5000: "AirPlay Receiver, on by default",
    7000: "AirPlay Receiver, on by default",
}

_SOCKET_CACHE = {}


def listening_sockets():
    """[{'port': int, 'addr': str, 'proc': str, 'pid': str}] for TCP listeners."""
    if "v" in _SOCKET_CACHE:
        return _SOCKET_CACHE["v"]

    socks = []
    if IS_MAC:
        rc, out, _ = run(["lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=15)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            addr_port = None
            for tok in reversed(parts):
                m = re.match(r"^(.*):(\d+)$", tok)
                if m:
                    addr_port = m
                    break
            if not addr_port:
                continue
            socks.append({
                "addr": addr_port.group(1),
                "port": int(addr_port.group(2)),
                "proc": parts[0],
                "pid": parts[1],
            })
    else:
        rc, out, _ = run(["ss", "-tlnpH"], timeout=15)
        if rc != 0 or not out.strip():
            rc, out, _ = run(["netstat", "-tlnp"], timeout=15)
        for line in out.splitlines():
            m = re.search(r"(\S+):(\d+)\s+\S+:(?:\*|\d+)", line)
            if not m:
                continue
            proc, pid = "?", "?"
            pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if pm:
                proc, pid = pm.group(1), pm.group(2)
            else:
                pm = re.search(r"(\d+)/(\S+)\s*$", line)
                if pm:
                    pid, proc = pm.group(1), pm.group(2)
            socks.append({"addr": m.group(1), "port": int(m.group(2)),
                          "proc": proc, "pid": pid})

    # de-duplicate on (addr, port, proc)
    uniq, seen = [], set()
    for s in socks:
        key = (s["addr"], s["port"], s["proc"])
        if key not in seen:
            seen.add(key)
            uniq.append(s)
    _SOCKET_CACHE["v"] = uniq
    return uniq


def _is_public(addr: str) -> bool:
    a = addr.strip("[]")
    if a in {x.strip("[]") for x in LOOPBACK}:
        return False
    if a.startswith("127.") or a.startswith("fe80"):
        return False
    return True


@check("exposed-ports", "Services reachable from the network", "network", HIGH, 12)
def chk_exposed_ports():
    socks = listening_sockets()
    if not socks:
        return Result(SKIP, "could not enumerate listening sockets")

    public = [s for s in socks if _is_public(s["addr"])]
    if not public:
        return Result(PASS, "all %d listening %s bound to loopback only"
                      % (len(socks), plural(len(socks), "service")))

    by_port = {}
    for s in public:
        by_port.setdefault(s["port"], s)

    details, worst, risky = [], WARN, 0
    for port in sorted(by_port):
        s = by_port[port]
        scope = ("any network" if s["addr"].strip("[]") in {w.strip("[]") for w in WILDCARD}
                 else s["addr"])
        line = "tcp/%-6d %-22s <- %s" % (port, s["proc"][:22], scope)
        note = DANGEROUS_PORTS.get(port)
        if note:
            line += "   ** %s **" % note
            worst = FAIL
            risky += 1
        elif port in EXPECTED_SERVICES:
            line += "   (%s)" % EXPECTED_SERVICES[port]
        details.append(line)

    summary = "%d %s listening beyond loopback" % (len(by_port), plural(len(by_port), "service"))
    if risky:
        summary = "%d high-value %s exposed to the network (of %d listeners)" % (
            risky, plural(risky, "service"), len(by_port))

    return Result(
        worst,
        summary,
        details,
        fix=["# bind development servers to 127.0.0.1, not 0.0.0.0",
             "# then re-check with: lsof -nP -iTCP -sTCP:LISTEN" if IS_MAC else
             "# then re-check with: ss -tlnp"],
    )


def _sshd_config_text():
    parts = []
    for path in ["/etc/ssh/sshd_config"]:
        t = read_text(path)
        if t:
            parts.append(t)
    d = Path("/etc/ssh/sshd_config.d")
    try:
        for f in sorted(d.glob("*.conf")):
            t = read_text(f)
            if t:
                parts.append(t)
    except Exception:
        pass
    return "\n".join(parts)


def _sshd_setting(text, key):
    val = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"(?i)^%s\s+(\S+)" % re.escape(key), line)
        if m:
            val = m.group(1).lower()
    return val


@check("ssh-server", "SSH server exposure", "network", HIGH, 9)
def chk_ssh_server():
    all_socks = listening_sockets()
    if not all_socks:
        return Result(SKIP, "could not enumerate listening sockets")
    socks = [s for s in all_socks if s["port"] == 22]
    if not socks:
        return Result(PASS, "no SSH server is listening")

    public = [s for s in socks if _is_public(s["addr"])]
    cfg = _sshd_config_text()
    details, fix = [], []
    status = WARN if public else PASS

    if public:
        details.append("sshd accepts connections from the network, not just loopback")

    root_login = _sshd_setting(cfg, "PermitRootLogin")
    if root_login in ("yes", "without-password", "prohibit-password") and public:
        if root_login == "yes":
            details.append("PermitRootLogin yes - root can log in directly")
            fix.append("# /etc/ssh/sshd_config: PermitRootLogin no")
            status = FAIL

    pw_auth = _sshd_setting(cfg, "PasswordAuthentication")
    if pw_auth == "yes" and public:
        details.append("PasswordAuthentication yes - the host is brute-forceable")
        fix.append("# /etc/ssh/sshd_config: PasswordAuthentication no")
        status = FAIL

    if not cfg:
        details.append("sshd_config is not readable, so its policy was not checked")

    return Result(status,
                  "SSH is listening on %s" % ("a public interface" if public else "loopback"),
                  details, fix)


@check("docker-exposure", "Docker daemon exposure", "network", CRITICAL, 8)
def chk_docker_exposure():
    evidence, fix = [], []
    saw_docker = False

    dh = os.environ.get("DOCKER_HOST", "")
    if dh.startswith("tcp://"):
        saw_docker = True
        if os.environ.get("DOCKER_TLS_VERIFY") != "1":
            evidence.append("DOCKER_HOST=%s without DOCKER_TLS_VERIFY" % dh)

    daemon = read_text("/etc/docker/daemon.json")
    if daemon:
        saw_docker = True
        if "tcp://" in daemon:
            evidence.append("/etc/docker/daemon.json binds the API to a TCP socket")
            fix.append("# remove the tcp:// host from /etc/docker/daemon.json")

    socks = listening_sockets()
    for s in socks:
        if s["port"] in (2375, 2376) and _is_public(s["addr"]):
            saw_docker = True
            evidence.append("tcp/%d open to %s - the Docker API is root on this host"
                            % (s["port"], s["addr"]))

    sock = Path("/var/run/docker.sock")
    if sock.exists():
        saw_docker = True
        # Follow the symlink: Docker Desktop points this at a per-user socket, and a
        # symlink's own mode bits are meaningless. Connecting needs write, not read.
        try:
            m = stat.S_IMODE(sock.stat().st_mode)
        except OSError:
            m = None
        if m is not None and m & 0o002:
            evidence.append("the Docker socket is world-writable (%04o) - any local "
                            "account can start a privileged container" % m)
            fix.append("sudo chmod o-w %s" % sock.resolve())

    if evidence:
        return Result(FAIL, "the Docker API is reachable without authentication", evidence, fix)
    if saw_docker:
        if not socks:
            return Result(SKIP, "Docker is present but listening sockets could not be read")
        return Result(PASS, "Docker is local-socket only")
    return Result(SKIP, "Docker is not installed")


# ==========================================================================
# CREDENTIALS
# ==========================================================================

def _key_is_encrypted(text):
    """True / False / None (unknown) for an SSH private key blob."""
    if "Proc-Type: 4,ENCRYPTED" in text or "DEK-Info:" in text:
        return True
    if "BEGIN ENCRYPTED PRIVATE KEY" in text:
        return True
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(ln.strip() for ln in text.splitlines() if not ln.startswith("-----"))
        try:
            raw = base64.b64decode(body + "===")
        except Exception:
            return None
        magic = b"openssh-key-v1\x00"
        if not raw.startswith(magic):
            return None
        off = len(magic)
        length = int.from_bytes(raw[off:off + 4], "big")
        cipher = raw[off + 4:off + 4 + length]
        return cipher != b"none"
    return None


@check("ssh-keys", "SSH private key hygiene", "credentials", HIGH, 10)
def chk_ssh_keys():
    ssh_dir = HOME / ".ssh"
    if not ssh_dir.is_dir():
        return Result(SKIP, "no ~/.ssh directory")

    details, fix = [], []
    status = PASS

    dm = mode_of(ssh_dir)
    if dm is not None and dm & 0o077:
        details.append("~/.ssh is %04o - other users on this machine can read it" % dm)
        fix.append("chmod 700 ~/.ssh")
        status = FAIL

    keys = 0
    for f in sorted(ssh_dir.iterdir()):
        if f.is_dir() or f.suffix == ".pub" or f.name in ("known_hosts", "config", "authorized_keys"):
            continue
        head = read_text(f, 80) or ""
        if not head.startswith("-----BEGIN"):
            continue
        keys += 1
        text = read_text(f, 200_000) or ""

        m = mode_of(f)
        if m is not None and m & 0o077:
            details.append("%s is %04o - readable by other accounts" % (tilde(f), m))
            fix.append("chmod 600 %s" % tilde(f))
            status = FAIL

        enc = _key_is_encrypted(text)
        if enc is False:
            details.append("%s has no passphrase - copying the file is enough to use it" % tilde(f))
            fix.append("ssh-keygen -p -f %s" % tilde(f))
            if status != FAIL:
                status = WARN

        rc, out, _ = run(["ssh-keygen", "-l", "-f", str(f)])
        km = re.match(r"^(\d+)\s+\S+\s+.*\((\w+)\)", out.strip())
        if km:
            bits, ktype = int(km.group(1)), km.group(2).upper()
            if ktype == "DSA":
                details.append("%s is a DSA key - the algorithm is deprecated and disabled by modern OpenSSH" % tilde(f))
                status = FAIL
            elif ktype == "RSA" and bits < 3072:
                details.append("%s is RSA-%d - below the 3072-bit floor" % (tilde(f), bits))
                if status != FAIL:
                    status = WARN

    if keys == 0:
        return Result(SKIP, "no SSH private keys found")
    if status == PASS:
        return Result(PASS, "%d private %s: locked down and passphrase-protected"
                      % (keys, plural(keys, "key")))
    return Result(status, "%d of %d private %s %s attention"
                  % (len({d.split()[0] for d in details}), keys,
                     plural(keys, "key"), plural(keys, "needs", "need")),
                  details, fix)


SENSITIVE_PATHS = [
    (".aws/credentials", "AWS long-lived access keys"),
    (".netrc", "machine passwords used by curl/ftp"),
    (".pgpass", "PostgreSQL passwords"),
    (".my.cnf", "MySQL credentials"),
    (".git-credentials", "git tokens in cleartext"),
    (".npmrc", "npm registry token"),
    (".pypirc", "PyPI upload token"),
    (".docker/config.json", "container registry credentials"),
    (".kube/config", "Kubernetes cluster credentials"),
    (".config/gh/hosts.yml", "GitHub CLI token"),
    (".terraformrc", "Terraform Cloud token"),
    (".cargo/credentials.toml", "crates.io token"),
    (".config/rclone/rclone.conf", "cloud storage credentials"),
    (".gnupg", "GPG private keyring"),
    (".ssh", "SSH keys"),
    (".zsh_history", "shell history"),
    (".bash_history", "shell history"),
]


@check("file-permissions", "Credential file permissions", "credentials", HIGH, 8)
def chk_file_permissions():
    details, fix = [], []
    checked = 0
    for rel, what in SENSITIVE_PATHS:
        p = HOME / rel
        if not p.exists():
            continue
        checked += 1
        m = mode_of(p)
        if m is None or not (m & 0o077):
            continue
        who = []
        if m & 0o070:
            who.append("group")
        if m & 0o007:
            who.append("others")
        target = "700" if p.is_dir() else "600"
        details.append("%s is %04o - %s can read %s" % (tilde(p), m, " and ".join(who), what))
        fix.append("chmod %s %s" % (target, tilde(p)))
    if not checked:
        return Result(SKIP, "no credential files present")
    if details:
        return Result(FAIL, "%d credential %s readable by other accounts"
                      % (len(details), plural(len(details), "file")), details, fix)
    return Result(PASS, "all %d credential files are owner-only" % checked)


@check("plaintext-credentials", "Tokens stored in cleartext", "credentials", HIGH, 9)
def chk_plaintext_credentials():
    details = []
    fix = []

    npmrc = read_text(HOME / ".npmrc", 200_000)
    if npmrc and re.search(r"_authToken\s*=\s*\S+", npmrc):
        details.append("~/.npmrc holds a registry token in cleartext")

    pypirc = read_text(HOME / ".pypirc", 200_000)
    if pypirc and re.search(r"(?i)^\s*password\s*[:=]\s*\S+", pypirc, re.M):
        details.append("~/.pypirc holds an upload token in cleartext")

    netrc = read_text(HOME / ".netrc", 200_000)
    if netrc and re.search(r"(?i)\bpassword\s+\S+", netrc):
        hosts = re.findall(r"(?i)\bmachine\s+(\S+)", netrc)
        details.append("~/.netrc stores passwords for %s" % (", ".join(hosts[:4]) or "one or more hosts"))

    gitcred = read_text(HOME / ".git-credentials", 200_000)
    if gitcred and gitcred.strip():
        hosts = re.findall(r"@([^/\s]+)", gitcred)
        details.append("~/.git-credentials stores git tokens in cleartext for %s"
                       % (", ".join(sorted(set(hosts))[:4]) or "one or more hosts"))
        fix.append("git config --global --unset credential.helper && rm ~/.git-credentials")

    dockercfg = read_text(HOME / ".docker/config.json", 200_000)
    if dockercfg:
        try:
            cfg = json.loads(dockercfg)
        except Exception:
            cfg = {}
        auths = cfg.get("auths") or {}
        raw = [r for r, v in auths.items() if isinstance(v, dict) and v.get("auth")]
        if raw and not cfg.get("credsStore"):
            details.append("~/.docker/config.json stores base64 registry logins for %s (no credsStore)"
                           % ", ".join(raw[:3]))
            fix.append("docker logout <registry>  # then configure a credsStore")

    aws = read_text(HOME / ".aws/credentials", 200_000)
    if aws:
        profiles = re.findall(r"^\s*\[([^\]]+)\]", aws, re.M)
        if re.search(r"(?i)aws_secret_access_key", aws):
            details.append("~/.aws/credentials holds long-lived keys for %d %s (%s)"
                           % (len(profiles), plural(len(profiles), "profile"),
                              ", ".join(profiles[:3])))
            fix.append("# prefer short-lived creds: aws sso login / aws configure sso")

    if details:
        return Result(WARN, "%d credential %s kept unencrypted on disk"
                      % (len(details), plural(len(details), "store")), details, fix)
    return Result(PASS, "no cleartext credential stores found")


@check("git-config", "Git credential handling", "credentials", HIGH, 6)
def chk_git_config():
    rc, out, _ = run(["git", "config", "--global", "--get", "credential.helper"])
    if rc == 127:
        return Result(SKIP, "git is not installed")
    helper = out.strip()

    details, fix = [], []
    status = PASS

    if helper == "store":
        details.append("credential.helper=store writes tokens to ~/.git-credentials in cleartext")
        fix.append("git config --global credential.helper %s"
                   % ("osxkeychain" if IS_MAC else "libsecret"))
        status = FAIL

    _, ssl, _ = run(["git", "config", "--global", "--get", "http.sslVerify"])
    if ssl.strip().lower() == "false":
        details.append("http.sslVerify=false - every git fetch and push accepts any certificate")
        fix.append("git config --global --unset http.sslVerify")
        status = FAIL

    if status == PASS:
        return Result(PASS, "git credentials go through %s"
                      % (helper if helper else "no persistent helper"))
    return Result(status, "git is configured to handle credentials unsafely", details, fix)


@check("shell-history", "Secrets in shell history", "credentials", HIGH, 9)
def chk_shell_history():
    candidates = [
        ".zsh_history", ".bash_history", ".sh_history", ".zhistory",
        ".local/share/fish/fish_history", ".config/fish/fish_history",
        ".python_history", ".node_repl_history", ".psql_history", ".mysql_history",
    ]
    details = []
    total_lines = 0
    scanned = 0
    for rel in candidates:
        p = HOME / rel
        if not p.is_file():
            continue
        scanned += 1
        text = tail_text(p, 3_000_000)
        if not text:
            continue
        hits, count = scan_history_lines(text.splitlines())
        total_lines += count
        for label, token, cmd in hits:
            details.append("%s: %s in `%s ...` -> %s" % (tilde(p), label, cmd, token))

    if not scanned:
        return Result(SKIP, "no shell history files found")
    if total_lines:
        return Result(
            FAIL,
            "%d history %s contain credentials in cleartext"
            % (total_lines, plural(total_lines, "line")),
            details[:8],
            fix=["# scrub the offending lines, then rotate every credential listed above",
                 "# prevent recurrence (zsh): setopt HIST_IGNORE_SPACE, then prefix secrets with a space"],
        )
    return Result(PASS, "no credentials found across %d history %s"
                  % (scanned, plural(scanned, "file")))


BENIGN_ENV = re.compile(r"(?i)^(?:.*_(?:FILE|PATH|DIR|URL|HOST|NAME|ID)|GPG_TTY|SSH_AUTH_SOCK)$")


@check("env-secrets", "Secrets in the environment", "credentials", MEDIUM, 6)
def chk_env_secrets():
    details = []
    for key, value in sorted(os.environ.items()):
        if not value or len(value) < 8 or BENIGN_ENV.match(key):
            continue
        hits = scan_secrets(value, max_hits=1)
        if hits:
            details.append("$%s holds a %s -> %s" % (key, hits[0][0], hits[0][1]))
        elif re.search(r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY)", key):
            details.append("$%s looks like a credential -> %s" % (key, redact(value)))
    if details:
        return Result(
            WARN,
            "%d environment %s credentials into every process you launch"
            % (len(details), plural(len(details), "variable carries", "variables carry")),
            details[:8],
            fix=["# move these into a secret manager or a 600-mode file sourced on demand"],
        )
    return Result(PASS, "no credentials exported into the environment")


PRUNE_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "Library", ".cache", ".Trash",
    "venv", ".venv", "env", "site-packages", "vendor", "dist", "build",
    "target", "Pods", ".gradle", ".terraform", "__pycache__", ".next",
    ".nuxt", "Applications", ".npm", ".rustup", ".cargo", "go",
    "Photos Library.photoslibrary", ".local", ".m2", ".pyenv", ".nvm",
}

DOTENV_RE = re.compile(r"^\.env(?:\..+)?$|^env(?:\.[a-z]+)?\.local$")
DOTENV_SAFE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults?)$")


def walk_home(max_depth, file_budget=40_000):
    """Yield (Path, depth) for files under $HOME, pruning noisy trees."""
    seen_files = 0
    stack = [(HOME, 0)]
    while stack:
        base, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            entries = list(os.scandir(base))
        except (PermissionError, OSError):
            continue
        for e in entries:
            if seen_files > file_budget:
                return
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.name in PRUNE_DIRS:
                        continue
                    stack.append((Path(e.path), depth + 1))
                else:
                    seen_files += 1
                    yield Path(e.path), depth
            except OSError:
                continue


def _git_root(path):
    p = path.parent
    for _ in range(12):
        if (p / ".git").exists():
            return p
        if p == p.parent:
            break
        p = p.parent
    return None


@check("dotenv-exposure", "Exposed .env files", "credentials", CRITICAL, 10)
def chk_dotenv_exposure():
    depth = 7 if DEEP_MODE else 4
    found = []
    for path, _ in walk_home(depth):
        name = path.name
        if not DOTENV_RE.match(name) or DOTENV_SAFE.search(name):
            continue
        found.append(path)
        if len(found) >= 400:
            break

    if not found:
        return Result(PASS, "no .env files found within %d levels of $HOME" % depth)

    committed, loose_perms, with_secrets = [], [], []
    git_budget = 60

    for path in found:
        m = mode_of(path)
        if m is not None and m & 0o077:
            loose_perms.append("%s is %04o" % (tilde(path), m))

        if git_budget > 0:
            root = _git_root(path)
            if root is not None:
                git_budget -= 1
                try:
                    rel = str(path.relative_to(root))
                except ValueError:
                    rel = str(path)
                rc, _, _ = run(["git", "-C", str(root), "ls-files",
                                "--error-unmatch", "--", rel], timeout=6)
                if rc == 0:
                    committed.append(tilde(path))

        text = read_text(path, 100_000)
        if text:
            hits = scan_secrets(text, max_hits=1)
            if hits:
                with_secrets.append("%s -> %s (%s)" % (tilde(path), hits[0][1], hits[0][0]))

    details, fix = [], []
    status = PASS

    if committed:
        status = FAIL
        details.append("%d .env %s tracked by git - they travel with every clone and push:"
                       % (len(committed), plural(len(committed), "file is", "files are")))
        details.extend("    " + c for c in committed[:6])
        fix.append("git rm --cached .env && echo '.env' >> .gitignore")
        fix.append("# already pushed? rotate those credentials, history rewriting is not enough")

    if loose_perms:
        if status != FAIL:
            status = WARN
        details.append("%d .env %s readable by other accounts: %s"
                       % (len(loose_perms), plural(len(loose_perms), "file is", "files are"),
                          ", ".join(loose_perms[:4])))
        fix.append("chmod 600 <file>")

    if with_secrets and status == PASS:
        status = WARN

    summary = "%d .env %s found" % (len(found), plural(len(found), "file"))
    if committed:
        summary = "%d .env %s committed to git" % (len(committed),
                                                   plural(len(committed), "file is", "files are"))
    elif loose_perms:
        summary = "%d .env %s readable by other accounts" % (
            len(loose_perms), plural(len(loose_perms), "file is", "files are"))
    elif with_secrets:
        summary = "%d .env %s live secrets" % (
            len(with_secrets), plural(len(with_secrets), "file holds", "files hold"))
    if not details:
        details.append("%d file%s found, all owner-only and untracked"
                       % (len(found), "" if len(found) == 1 else "s"))

    return Result(status, summary, details, fix)


# ==========================================================================
# BROWSER
# ==========================================================================

# Permissions that let an extension read or alter everything you do.
RISKY_PERMISSIONS = {
    "<all_urls>": "read and modify every site you visit",
    "http://*/*": "read and modify every site you visit",
    "https://*/*": "read and modify every site you visit",
    "*://*/*": "read and modify every site you visit",
    "debugger": "attach a debugger to any page",
    "nativeMessaging": "talk to native programs outside the browser",
    "proxy": "reroute all your traffic",
    "cookies": "read your session cookies",
    "webRequest": "intercept every network request",
    "webRequestBlocking": "intercept and rewrite network requests",
    "management": "install, disable and remove other extensions",
    "clipboardRead": "read your clipboard",
    "history": "read your full browsing history",
    "desktopCapture": "capture your screen",
    "tabCapture": "capture tab audio and video",
    "privacy": "change your privacy settings",
}

TOP_RISK = {"<all_urls>", "http://*/*", "https://*/*", "*://*/*",
            "debugger", "nativeMessaging", "proxy"}


def _chromium_roots():
    if IS_MAC:
        base = HOME / "Library/Application Support"
        rels = ["Google/Chrome", "Google/Chrome Beta", "Chromium",
                "BraveSoftware/Brave-Browser", "Microsoft Edge",
                "Vivaldi", "Arc/User Data", "Opera Software/Opera Stable"]
    else:
        base = HOME / ".config"
        rels = ["google-chrome", "chromium", "BraveSoftware/Brave-Browser",
                "microsoft-edge", "vivaldi", "opera"]
    return [(rel.split("/")[-1].replace("-", " "), base / rel)
            for rel in rels if (base / rel).is_dir()]


def _resolve_msg_name(ext_dir, manifest):
    name = manifest.get("name", "")
    if not (name.startswith("__MSG_") and name.endswith("__")):
        return name or ext_dir.parent.name
    key = name[6:-2]
    locale = manifest.get("default_locale", "en")
    for loc in (locale, "en", "en_US"):
        msgs = read_text(ext_dir / "_locales" / loc / "messages.json", 400_000)
        if not msgs:
            continue
        try:
            data = json.loads(msgs)
        except Exception:
            continue
        for k, v in data.items():
            if k.lower() == key.lower() and isinstance(v, dict):
                return v.get("message", key)
    return key


def _scan_chromium(browser, root):
    out = []
    try:
        profiles = [p for p in root.iterdir()
                    if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile"))]
    except Exception:
        return out
    for profile in profiles:
        ext_root = profile / "Extensions"
        if not ext_root.is_dir():
            continue
        try:
            ext_ids = [d for d in ext_root.iterdir() if d.is_dir()]
        except Exception:
            continue
        for ext_id in ext_ids:
            try:
                versions = sorted([v for v in ext_id.iterdir() if v.is_dir()])
            except Exception:
                continue
            if not versions:
                continue
            vdir = versions[-1]
            raw = read_text(vdir / "manifest.json", 600_000)
            if not raw:
                continue
            try:
                manifest = json.loads(raw)
            except Exception:
                continue
            perms = set()
            for key in ("permissions", "host_permissions", "optional_permissions",
                        "optional_host_permissions"):
                for p in manifest.get(key, []) or []:
                    if isinstance(p, str):
                        perms.add(p)
            risky = sorted(perms & set(RISKY_PERMISSIONS))
            if not risky:
                continue
            out.append({
                "browser": browser,
                "name": _resolve_msg_name(vdir, manifest)[:40],
                "id": ext_id.name,
                "risky": risky,
                "top": bool(set(risky) & TOP_RISK),
            })
    return out


def _scan_firefox():
    out = []
    if IS_MAC:
        base = HOME / "Library/Application Support/Firefox/Profiles"
    else:
        base = HOME / ".mozilla/firefox"
    if not base.is_dir():
        return out
    try:
        profiles = [p for p in base.iterdir() if p.is_dir()]
    except Exception:
        return out
    for profile in profiles:
        raw = read_text(profile / "extensions.json", 4_000_000)
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        for addon in data.get("addons", []) or []:
            if addon.get("type") != "extension" or addon.get("userDisabled"):
                continue
            if addon.get("location") not in (None, "app-profile", "app-system-defaults"):
                pass
            perms = set((addon.get("userPermissions") or {}).get("permissions", []) or [])
            perms |= set((addon.get("userPermissions") or {}).get("origins", []) or [])
            risky = sorted(perms & set(RISKY_PERMISSIONS))
            if not risky:
                continue
            name = (addon.get("defaultLocale") or {}).get("name") or addon.get("id", "?")
            out.append({
                "browser": "Firefox",
                "name": str(name)[:40],
                "id": addon.get("id", "?"),
                "risky": risky,
                "top": bool(set(risky) & TOP_RISK),
            })
    return out


@check("browser-extensions", "Over-privileged browser extensions", "browser", HIGH, 8)
def chk_browser_extensions():
    found = []
    roots = _chromium_roots()
    for browser, root in roots:
        found.extend(_scan_chromium(browser, root))
    found.extend(_scan_firefox())

    firefox_present = (HOME / "Library/Application Support/Firefox").is_dir() or \
                      (HOME / ".mozilla/firefox").is_dir()
    if not roots and not firefox_present:
        return Result(SKIP, "no supported browser profiles found")

    if not found:
        return Result(PASS, "no extension requests a high-risk permission")

    found.sort(key=lambda e: (not e["top"], -len(e["risky"]), e["name"].lower()))
    total_access = [e for e in found if e["top"]]

    details = []
    for e in found[:6]:
        why = RISKY_PERMISSIONS[e["risky"][0]]
        details.append("%s [%s] can %s  (%s)"
                       % (e["name"], e["browser"], why, ", ".join(e["risky"][:4])))
    if len(found) > 6:
        details.append("... and %d more" % (len(found) - 6))

    status = FAIL if total_access else WARN
    return Result(
        status,
        "%d %s hold permissions that expose everything you browse"
        % (len(found), plural(len(found), "extension")),
        details,
        fix=["# audit them: chrome://extensions  (Details > Site access > On click)",
             "# remove anything you do not actively use"],
    )


# ==========================================================================
# scoring
# ==========================================================================

DEEP_MODE = False

STATUS_CREDIT = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}


def score_of(findings):
    earned = total = 0.0
    for f in findings:
        if f.status == SKIP:
            continue
        total += f.weight
        earned += f.weight * STATUS_CREDIT.get(f.status, 0.0)
    if total <= 0:
        return 0, 0
    return int(round(100.0 * earned / total)), int(total)


GRADES = [
    (90, "LEAD LINED", COLOR_OK),
    (75, "SOLID FOIL", COLOR_OK),
    (55, "CRINKLED", COLOR_MED),
    (35, "THIN", COLOR_HIGH),
    (0, "TRANSPARENT", COLOR_CRIT),
]


def grade_of(score):
    for floor, label, color in GRADES:
        if score >= floor:
            return label, color
    return GRADES[-1][1], GRADES[-1][2]


# ==========================================================================
# rendering
# ==========================================================================

GLYPHS = {FAIL: "✗", WARN: "!", PASS: "✓", SKIP: "·"}

DIGITS = {
    "0": ["█████", "█   █", "█   █", "█   █", "█████"],
    "1": ["  ██ ", " ███ ", "  ██ ", "  ██ ", " ████"],
    "2": ["█████", "    █", "█████", "█    ", "█████"],
    "3": ["█████", "    █", "█████", "    █", "█████"],
    "4": ["█   █", "█   █", "█████", "    █", "    █"],
    "5": ["█████", "█    ", "█████", "    █", "█████"],
    "6": ["█████", "█    ", "█████", "█   █", "█████"],
    "7": ["█████", "    █", "   █ ", "  █  ", "  █  "],
    "8": ["█████", "█   █", "█████", "█   █", "█████"],
    "9": ["█████", "█   █", "█████", "    █", "█████"],
}

LOGO = [
    "▀█▀ █ █▄ █ █▀▀ █▀█ █ █  ",
    " █  █ █ ▀█ █▀  █▄█ █ █▄▄",
]


def term_width(default=92):
    try:
        return max(60, min(os.get_terminal_size().columns, 100))
    except Exception:
        return default


def big_number(n):
    rows = ["", "", "", "", ""]
    for i, ch in enumerate(str(n)):
        glyph = DIGITS.get(ch, DIGITS["0"])
        for r in range(5):
            rows[r] += ("  " if i else "") + glyph[r]
    return rows


def gauge(score, width=26):
    filled = int(round(width * score / 100.0))
    return "█" * filled + "░" * (width - filled)


def emit(line=""):
    sys.stdout.write(line + "\n")


def clip(text, width):
    """Trim to `width`, preferring a word boundary, with a visible ellipsis."""
    if len(text) <= width:
        return text
    cut = text[:width - 1]
    space = cut.rfind(" ")
    if space > width * 0.6:
        cut = cut[:space]
    return cut + "\u2026"


def render_header():
    emit()
    emit("  " + ink.bold_fg(COLOR_ACCENT, LOGO[0]))
    emit("  " + ink.bold_fg(COLOR_ACCENT, LOGO[1]) + "  "
         + ink.dim("v%s  ·  %s %s" % (__version__, SYSTEM, platform.release())))
    emit()


def render_score(findings, elapsed):
    score, _ = score_of(findings)
    label, color = grade_of(score)
    counts = {s: len([f for f in findings if f.status == s]) for s in (FAIL, WARN, PASS, SKIP)}

    rows = big_number(score)
    side = [
        ink.dim("PARANOIA SCORE"),
        ink.bold_fg(color, label),
        ink.fg(color, gauge(score)) + ink.dim("  %d/100" % score),
        "%s   %s   %s" % (
            ink.fg(COLOR_CRIT, "%d failed" % counts[FAIL]),
            ink.fg(COLOR_MED, "%d warning%s" % (counts[WARN], "" if counts[WARN] == 1 else "s")),
            ink.fg(COLOR_OK, "%d passed" % counts[PASS]),
        ),
        ink.dim("%d checks in %.1fs · %d skipped" % (len(findings), elapsed, counts[SKIP])),
    ]
    for i in range(5):
        emit("   " + ink.bold_fg(color, rows[i]) + "    " + side[i])
    emit()


def render_finding(f, width):
    glyph = GLYPHS[f.status]
    color = {FAIL: SEV_COLOR[f.severity], WARN: COLOR_MED,
             PASS: COLOR_OK, SKIP: COLOR_DIM}[f.status]
    sev = f.severity.upper() if f.status == FAIL else (
        "WARN" if f.status == WARN else ("OK" if f.status == PASS else "SKIP"))

    left_plain = "  %s  %-9s %s" % (glyph, sev, f.summary)
    left = "  %s  %s %s" % (
        ink.bold_fg(color, glyph),
        ink.bold_fg(color, "%-9s" % sev),
        f.summary if f.status in (FAIL, WARN) else ink.dim(f.summary),
    )
    pad = max(1, width - len(left_plain) - len(f.id) - 2)
    emit(left + " " * pad + ink.dim(f.id))

    if f.status in (FAIL, WARN):
        for d in f.details[:8]:
            emit("     " + ink.dim("│ ") + ink.fg(COLOR_DIM, clip(d, width - 8)))
        if len(f.details) > 8:
            emit("     " + ink.dim("│ ... and %d more" % (len(f.details) - 8)))


def render_report(findings, elapsed, show_passes=True, show_skipped=False, show_fixes=True):
    width = term_width()
    render_header()
    render_score(findings, elapsed)

    for cat in CATEGORIES:
        group = [f for f in findings if f.category == cat]
        if not group:
            continue
        visible = [f for f in group
                   if f.status in (FAIL, WARN)
                   or (f.status == PASS and show_passes)
                   or (f.status == SKIP and show_skipped)]
        if not visible:
            continue
        rule = "─" * max(4, width - len(CATEGORY_LABELS[cat]) - 6)
        emit("  " + ink.dim("── ") + ink.bold(CATEGORY_LABELS[cat]) + " " + ink.dim(rule))
        visible.sort(key=lambda f: (STATUS_RANK[f.status], SEV_RANK[f.severity], f.id))
        for f in visible:
            render_finding(f, width)
        emit()

    if show_fixes:
        broken = [f for f in findings if f.status in (FAIL, WARN) and f.fix]
        broken.sort(key=lambda f: (STATUS_RANK[f.status], SEV_RANK[f.severity], -f.weight))
        if broken:
            emit("  " + ink.dim("── ") + ink.bold("FIX FIRST") + " "
                 + ink.dim("─" * max(4, width - 15)))
            for f in broken[:6]:
                emit("  " + ink.bold_fg(SEV_COLOR[f.severity], "• ") + f.title)
                for cmd in f.fix[:2]:
                    emit("      " + ink.fg(COLOR_ACCENT, clip(cmd, width - 8)))
            emit()

    skipped = [f for f in findings if f.status == SKIP]
    if skipped and not show_skipped:
        emit("  " + ink.dim("%d check%s skipped (%s) · re-run with --all to see why"
                            % (len(skipped), "" if len(skipped) == 1 else "s",
                               ", ".join(f.id for f in skipped[:4]))))
    emit("  " + ink.dim("no network calls were made · nothing left this machine"))
    emit()


def to_json(findings, elapsed):
    score, weight = score_of(findings)
    label, _ = grade_of(score)
    return json.dumps({
        "tinfoil": __version__,
        "platform": "%s %s" % (SYSTEM, platform.release()),
        "generated_at": int(time.time()),
        "duration_s": round(elapsed, 3),
        "score": score,
        "grade": label,
        "weight_considered": weight,
        "counts": {s: len([f for f in findings if f.status == s])
                   for s in (FAIL, WARN, PASS, SKIP)},
        "findings": [
            {
                "id": f.id, "title": f.title, "category": f.category,
                "severity": f.severity, "weight": f.weight, "status": f.status,
                "summary": f.summary, "details": f.details, "fix": f.fix,
                "duration_ms": f.ms,
            }
            for f in findings
        ],
    }, indent=2)


# ==========================================================================
# runner
# ==========================================================================

def load_plugins():
    """Load extra checks from ~/.tinfoil/checks/*.py (same trust level as .zshrc)."""
    plugin_dir = HOME / ".tinfoil" / "checks"
    if not plugin_dir.is_dir():
        return 0
    loaded = 0
    for path in sorted(plugin_dir.glob("*.py")):
        namespace = {
            "check": check, "Result": Result, "run": run, "read_text": read_text,
            "tail_text": tail_text, "mode_of": mode_of, "tilde": tilde,
            "redact": redact, "scan_secrets": scan_secrets, "HOME": HOME,
            "IS_MAC": IS_MAC, "IS_LINUX": IS_LINUX,
            "CRITICAL": CRITICAL, "HIGH": HIGH, "MEDIUM": MEDIUM, "LOW": LOW,
            "FAIL": FAIL, "WARN": WARN, "PASS": PASS, "SKIP": SKIP,
            "__name__": "tinfoil_plugin_%s" % path.stem,
        }
        try:
            exec(compile(path.read_text(), str(path), "exec"), namespace)
            loaded += 1
        except Exception as exc:
            sys.stderr.write("tinfoil: plugin %s failed to load: %s\n" % (path.name, exc))
    return loaded


def _run_one(c):
    started = time.time()
    try:
        res = c.func()
        if not isinstance(res, Result):
            res = Result(SKIP, "check returned no result")
    except Exception as exc:
        res = Result(SKIP, "check raised %s: %s" % (type(exc).__name__, exc))
    return Finding(
        id=c.id, title=c.title, category=c.category, severity=c.severity,
        weight=c.weight, status=res.status, summary=res.summary,
        details=list(res.details), fix=list(res.fix),
        ms=int((time.time() - started) * 1000),
    )


def run_checks(only=None, skip=None, deep=False):
    selected = [
        c for c in CHECKS
        if SYSTEM in c.platforms
        and not (only and c.id not in only)
        and not (skip and c.id in skip)
        and not (c.deep and not deep)
    ]
    if not selected:
        return []

    # Almost every check waits on a subprocess or the filesystem, so a small
    # thread pool collapses the wall clock to roughly the slowest single check.
    # Warm the shared socket cache first: three checks read it concurrently.
    try:
        listening_sockets()
    except Exception:
        pass

    if len(selected) == 1:
        return [_run_one(selected[0])]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        # Results are collected in submission order, so output stays deterministic.
        return list(pool.map(_run_one, selected))


def demo_findings():
    """Synthetic report used for screenshots and for previewing the output."""
    d = lambda *a, **k: Finding(*a, **k)
    return [
        d("disk-encryption", "Full-disk encryption", "system", CRITICAL, 12,
          PASS, "FileVault is on", [], []),
        d("firewall", "Host firewall", "system", HIGH, 8,
          FAIL, "application firewall is disabled", [],
          ["sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"]),
        d("sip", "System Integrity Protection", "system", HIGH, 8,
          PASS, "SIP is enabled", [], []),
        d("gatekeeper", "Gatekeeper", "system", HIGH, 7, PASS, "Gatekeeper is enforcing", [], []),
        d("screen-lock", "Screen lock on wake", "system", MEDIUM, 6,
          PASS, "password required on wake", [], []),
        d("path-hygiene", "$PATH integrity", "system", HIGH, 7,
          FAIL, "1 unsafe $PATH entry",
          ["/usr/local/bin is world-writable (0777) - any local account can replace a command you run"],
          ["chmod o-w /usr/local/bin"]),
        d("stale-uptime", "Time since last reboot", "system", LOW, 3,
          WARN, "up for 63 days - pending kernel updates are not active yet", [], []),
        d("exposed-ports", "Services reachable from the network", "network", HIGH, 12,
          FAIL, "2 high-value services exposed to the network (of 3 listeners)",
          ["tcp/5432   postgres           <- any network   ** PostgreSQL database **",
           "tcp/6379   redis-server       <- any network   ** Redis - usually unauthenticated by default **",
           "tcp/8080   node               <- any network"],
          ["# bind development servers to 127.0.0.1, not 0.0.0.0"]),
        d("ssh-server", "SSH server exposure", "network", HIGH, 9,
          PASS, "no SSH server is listening", [], []),
        d("docker-exposure", "Docker daemon exposure", "network", CRITICAL, 8,
          PASS, "Docker is local-socket only", [], []),
        d("dotenv-exposure", "Exposed .env files", "credentials", CRITICAL, 10,
          FAIL, "2 .env files are committed to git",
          ["2 .env files are tracked by git - they travel with every clone and push:",
           "    ~/code/billing-api/.env",
           "    ~/code/dashboard/.env.production"],
          ["git rm --cached .env && echo '.env' >> .gitignore",
           "# already pushed? rotate those credentials, history rewriting is not enough"]),
        d("shell-history", "Secrets in shell history", "credentials", HIGH, 9,
          FAIL, "4 history lines contain credentials in cleartext",
          ["~/.zsh_history: AWS access key in `aws ...` -> AKIA**********7Q",
           "~/.zsh_history: GitHub token in `curl ...` -> ghp_**********xE",
           "~/.bash_history: inline basic auth in `curl ...` -> user**********rd"],
          ["# scrub the offending lines, then rotate every credential listed above"]),
        d("ssh-keys", "SSH private key hygiene", "credentials", HIGH, 10,
          WARN, "1 of 3 private keys needs attention",
          ["~/.ssh/id_rsa has no passphrase - copying the file is enough to use it",
           "~/.ssh/id_rsa is RSA-2048 - below the 3072-bit floor"],
          ["ssh-keygen -p -f ~/.ssh/id_rsa"]),
        d("file-permissions", "Credential file permissions", "credentials", HIGH, 8,
          FAIL, "1 credential file readable by other accounts",
          ["~/.aws/credentials is 0644 - group and others can read AWS long-lived access keys"],
          ["chmod 600 ~/.aws/credentials"]),
        d("git-config", "Git credential handling", "credentials", HIGH, 6,
          PASS, "git credentials go through osxkeychain", [], []),
        d("plaintext-credentials", "Tokens stored in cleartext", "credentials", HIGH, 9,
          WARN, "2 credential stores kept unencrypted on disk",
          ["~/.npmrc holds a registry token in cleartext",
           "~/.docker/config.json stores base64 registry logins for ghcr.io (no credsStore)"],
          ["docker logout <registry>  # then configure a credsStore"]),
        d("env-secrets", "Secrets in the environment", "credentials", MEDIUM, 6,
          PASS, "no credentials exported into the environment", [], []),
        d("browser-extensions", "Over-privileged browser extensions", "browser", HIGH, 8,
          FAIL, "5 extensions hold permissions that expose everything you browse",
          ["Coupon Finder Pro [Chrome] can read and modify every site you visit  (<all_urls>, cookies, webRequest)",
           "PDF Toolkit [Chrome] can talk to native programs outside the browser  (nativeMessaging)",
           "Dark Mode Everywhere [Brave] can read and modify every site you visit  (<all_urls>)",
           "... and 2 more"],
          ["# audit them: chrome://extensions  (Details > Site access > On click)"]),
    ]


def main(argv=None):
    global ink, DEEP_MODE

    parser = argparse.ArgumentParser(
        prog="tinfoil",
        description="Audit this machine's attack surface. Runs entirely offline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  tinfoil                       full report\n"
               "  tinfoil --demo                sample report, synthetic data\n"
               "  tinfoil --only ssh-keys       run a single check\n"
               "  tinfoil --json > report.json  machine-readable output\n"
               "  tinfoil --fail-under 80       exit 1 when the score is too low (CI)\n",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    parser.add_argument("--demo", action="store_true", help="render a sample report with synthetic data")
    parser.add_argument("--deep", action="store_true", help="slower, wider filesystem scan")
    parser.add_argument("--only", metavar="IDS", help="comma-separated check ids to run")
    parser.add_argument("--skip", metavar="IDS", help="comma-separated check ids to skip")
    parser.add_argument("--list", action="store_true", help="list every check and exit")
    parser.add_argument("--quiet", action="store_true", help="hide passing checks")
    parser.add_argument("--all", action="store_true", help="also show skipped checks")
    parser.add_argument("--no-fix", action="store_true", help="omit the remediation section")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--fail-under", type=int, metavar="N",
                        help="exit 1 if the score is below N")
    parser.add_argument("--version", action="version", version="tinfoil %s" % __version__)
    args = parser.parse_args(argv)

    ink = Ink(supports_color(args.color))
    DEEP_MODE = args.deep
    load_plugins()

    if args.list:
        for c in sorted(CHECKS, key=lambda c: (CATEGORIES.index(c.category)
                                               if c.category in CATEGORIES else 9, c.id)):
            plats = "any" if len(c.platforms) > 1 else c.platforms[0]
            emit("  %-22s %-12s %-9s w=%-3d %s" % (c.id, c.category, c.severity, c.weight, plats))
        return 0

    only = {s.strip() for s in args.only.split(",")} if args.only else None
    skip = {s.strip() for s in args.skip.split(",")} if args.skip else None

    if not args.demo and SYSTEM not in SUPPORTED_SYSTEMS:
        sys.stderr.write(
            "tinfoil: %s is not supported yet - it audits macOS and Linux.\n"
            "Under WSL it runs, but it audits the WSL Linux environment, not Windows itself.\n"
            "`tinfoil --demo` shows what a report looks like.\n" % (SYSTEM or "this platform"))
        return 2

    started = time.time()
    if args.demo:
        findings = demo_findings()
        elapsed = 2.4
    else:
        findings = run_checks(only=only, skip=skip, deep=args.deep)
        elapsed = time.time() - started

    if not findings:
        sys.stderr.write("tinfoil: no checks matched\n")
        return 2

    if args.json:
        emit(to_json(findings, elapsed))
    else:
        render_report(findings, elapsed,
                      show_passes=not args.quiet,
                      show_skipped=args.all,
                      show_fixes=not args.no_fix)

    if args.fail_under is not None:
        score, _ = score_of(findings)
        if score < args.fail_under:
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
