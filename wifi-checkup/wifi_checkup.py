#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi_checkup.py - a read-only checkup of your home Wi-Fi and internet.

It answers three questions:
  1. How healthy is my Wi-Fi connection (signal, band, channel, security)?
  2. How fast is my internet, and where is the slowdown: Wi-Fi, router or provider?
  3. Which devices are on my network right now, and is any of them new?

It changes NO settings on your computer or router. It only reads information
and sends ordinary network traffic (pings, DNS lookups and a speed test).

Works on Windows, macOS and Linux with Python 3.8 or newer. No extra packages.

    python3 wifi_checkup.py                 full checkup (about 1-2 minutes)
    python3 wifi_checkup.py --plan 100      compare with a 100 Mbps internet plan
    python3 wifi_checkup.py --no-speed      skip the speed test (saves data)
    python3 wifi_checkup.py --help          all options

On Windows use "py wifi_checkup.py" (or "python wifi_checkup.py").
"""

import argparse
import concurrent.futures
import datetime
import html
import ipaddress
import json
import locale
import os
import platform
import random
import re
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

IPV4_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
MAC_RE = r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5}(?![0-9A-Fa-f:-])"

PUBLIC_PING_TARGETS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")]
PUBLIC_DNS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")]
DNS_TEST_NAMES = ["google.com", "youtube.com", "wikipedia.org", "amazon.com",
                  "facebook.com", "netflix.com", "microsoft.com", "apple.com"]

SPEED_BASE_URL = "https://speed.cloudflare.com"
DOWNLOAD_REQUEST_BYTES = 50_000_000
USER_AGENT = "wifi-checkup/" + VERSION

AIRPORT_CMD = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")

WIN_LOCATION_HINT = (
    "Windows only shows Wi-Fi details to programs when Location is allowed. "
    "Open Settings > Privacy & security > Location, turn on 'Location services' "
    "and 'Let desktop apps access your location', then run this check again. "
    "(You can switch it back off afterwards.)")

MAC_LOCATION_HINT = (
    "macOS hid the Wi-Fi network name. That's fine - signal, channel and "
    "security were still read. To show the name, allow Location for Terminal in "
    "System Settings > Privacy & Security > Location Services.")

# Problems inside the checker itself. They are listed at the end of the report
# so one failed step never stops the rest of the checkup.
INTERNAL_ERRORS = []


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def decode_output(data):
    """Decode command output, trying the encodings Windows and Unix consoles use."""
    encodings = ["utf-8"]
    if IS_WIN:
        encodings += ["oem", "mbcs"]
    encodings.append(locale.getpreferredencoding(False) or "latin-1")
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def run(cmd, timeout=20, english=True):
    """Run a command and return its output as text ("" if it can't be run)."""
    env = None
    if english and not IS_WIN:
        env = dict(os.environ, LC_ALL="C", LANG="C")
    kwargs = {}
    if IS_WIN:
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, timeout=timeout, env=env, **kwargs)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return decode_output(proc.stdout or b"")


def safe(label, fn, *args, **kwargs):
    """Call fn; if it fails, note the problem and return None instead of crashing."""
    try:
        return fn(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # deliberately broad: keep the checkup going
        INTERNAL_ERRORS.append("%s: %s: %s" % (label, type(exc).__name__, exc))
        return None


def to_float(value):
    try:
        return float(str(value).strip().replace(",", "."))
    except (TypeError, ValueError):
        return None


def to_int(value):
    f = to_float(value)
    return int(round(f)) if f is not None else None


def is_ipv4(text):
    try:
        ipaddress.IPv4Address(str(text).strip())
        return True
    except ValueError:
        return False


def norm_mac(text):
    """'A0-B1-C2-D3-E4-F5' or 'a0:b1:c:d3:e4:5' -> 'a0:b1:c2:d3:e4:f5' (None if invalid)."""
    if not text:
        return None
    parts = re.split(r"[:-]", str(text).strip())
    if len(parts) != 6:
        return None
    try:
        values = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if any(v > 255 for v in values) or any(len(p) == 0 or len(p) > 2 for p in parts):
        return None
    return ":".join("%02x" % v for v in values)


def is_unicast_mac(mac):
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return not int(mac[:2], 16) & 1


def is_random_mac(mac):
    """Phones and laptops often use a 'private'/randomised address (locally administered bit)."""
    return bool(mac) and bool(int(mac[:2], 16) & 2)


def mask_to_prefix(mask):
    """'255.255.255.0' or '0xffffff00' -> 24."""
    mask = str(mask).strip()
    try:
        if mask.lower().startswith("0x"):
            mask = socket.inet_ntoa(struct.pack(">I", int(mask, 16)))
        return ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
    except (ValueError, struct.error, OSError):
        return None


def freq_to_channel(mhz):
    """Wi-Fi centre frequency in MHz -> (channel, band)."""
    if mhz is None:
        return None, None
    mhz = int(mhz)
    if mhz == 2484:
        return 14, "2.4 GHz"
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5, "2.4 GHz"
    if 5150 <= mhz <= 5895:
        return (mhz - 5000) // 5, "5 GHz"
    if 5925 <= mhz <= 7125:
        return (mhz - 5950) // 5, "6 GHz"
    return None, None


def band_from_channel(channel):
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    return None


def normalize_band(text):
    if not text:
        return None
    m = re.search(r"(2[.,]4|2|5|6)\s*GHz", str(text), re.I)
    if not m:
        return None
    return {"2": "2.4 GHz", "2.4": "2.4 GHz", "2,4": "2.4 GHz",
            "5": "5 GHz", "6": "6 GHz"}[m.group(1)]


def pct_to_dbm(pct):
    """Signal quality % (as Windows and NetworkManager show it) -> approximate dBm."""
    return int(round(pct / 2.0 - 100))


def signal_label(rssi):
    if rssi is None:
        return "unknown"
    if rssi >= -60:
        return "Strong"
    if rssi >= -67:
        return "Good"
    if rssi >= -75:
        return "Fair"
    return "Weak"


def wifi_generation(standard, band=None):
    m = re.search(r"802\.11\s*([a-z]+)", str(standard or ""), re.I)
    if not m:
        return None
    letters = m.group(1).lower()
    if "be" in letters:
        return "Wi-Fi 7"
    if "ax" in letters:
        return "Wi-Fi 6E" if band == "6 GHz" else "Wi-Fi 6"
    if "ac" in letters:
        return "Wi-Fi 5"
    if "n" in letters:
        return "Wi-Fi 4"
    if letters in ("a", "b", "g"):
        return "older than Wi-Fi 4"
    return None


def classify_security(security, cipher=None):
    """-> (level, label). level: critical / weak / fair / good / strong / unknown."""
    s = (security or "").strip().lower()
    c = (cipher or "").strip().lower()
    if not s:
        return "unknown", "unknown"
    label = security.strip()
    if "wep" in s or c == "wep":
        return "critical", label + " (WEP is obsolete and can be broken in minutes)"
    if s in ("open", "none", "--", "no security", "open (no password)"):
        return "critical", "Open - no password"
    if "owe" in s or "enhanced open" in s:
        return "fair", label + " (encrypted, but anyone can join)"
    if "enterprise" in s or "802.1x" in s or "eap" in s:
        return "strong", label
    if "wpa3" in s or "sae" in s:
        return "strong", label
    if "wpa2" in s or "rsn" in s:
        if "tkip" in c and "ccmp" not in c and "aes" not in c:
            return "weak", label + " with TKIP (old, slow encryption)"
        return "good", label
    if "wpa" in s:
        return "weak", label + " (first-generation WPA)"
    return "unknown", label


def clean_text(text, limit=60):
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", html.unescape(str(text or ""))).strip()
    text = re.sub(r"\s+", " ", text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


# --------------------------------------------------------------------------
# Network basics: router address, this computer's address, network range, DNS
# --------------------------------------------------------------------------

def parse_route_print(text):
    """Windows 'route print -4 0.0.0.0' -> (gateway, local_ip) of the lowest-metric default."""
    best = None
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0" and is_ipv4(p[2]):
            metric = int(p[4]) if p[4].isdigit() else 10 ** 6
            if best is None or metric < best[0]:
                best = (metric, p[2], p[3])
    return (best[1], best[2]) if best else (None, None)


def parse_route_get(text):
    """macOS 'route -n get default' -> (gateway, interface)."""
    gw = re.search(r"gateway:\s*(" + IPV4_RE + r")", text)
    ifc = re.search(r"interface:\s*(\S+)", text)
    return (gw.group(1) if gw else None, ifc.group(1) if ifc else None)


def parse_ip_route(text):
    """Linux 'ip -4 route show default' -> (gateway, interface)."""
    best = None
    for line in text.splitlines():
        line = line.strip()
        via = re.search(r"\bvia (" + IPV4_RE + r")", line)
        if not line.startswith("default") or not via:
            continue
        dev = re.search(r"\bdev (\S+)", line)
        metric = re.search(r"\bmetric (\d+)", line)
        m = int(metric.group(1)) if metric else 0
        if best is None or m < best[0]:
            best = (m, via.group(1), dev.group(1) if dev else None)
    return (best[1], best[2]) if best else (None, None)


def parse_proc_route(text):
    """Linux /proc/net/route -> (gateway, interface)."""
    best = None
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) < 7 or p[1] != "00000000":
            continue
        try:
            flags = int(p[3], 16)
            gateway = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
            metric = int(p[6])
        except (ValueError, struct.error, OSError):
            continue
        if not (flags & 0x1 and flags & 0x2):  # RTF_UP and RTF_GATEWAY
            continue
        if best is None or metric < best[0]:
            best = (metric, gateway, p[0])
    return (best[1], best[2]) if best else (None, None)


def parse_ps_routes(text):
    """PowerShell 'Get-NetRoute' lines 'nexthop metric' -> (gateway, None) with the lowest metric."""
    best = None
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 2 and is_ipv4(p[0]) and p[0] != "0.0.0.0" and p[1].isdigit():
            if best is None or int(p[1]) < best[0]:
                best = (int(p[1]), p[0])
    return (best[1], None) if best else (None, None)


def get_default_route():
    if IS_WIN:
        gw = parse_route_print(run(["route", "print", "-4"]))
        if gw[0]:
            return gw
        return parse_ps_routes(powershell(
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
            "ForEach-Object { $_.NextHop + ' ' + ($_.RouteMetric + $_.InterfaceMetric) }"))
    if IS_MAC:
        return parse_route_get(run(["route", "-n", "get", "default"]))
    gw = parse_ip_route(run(["ip", "-4", "route", "show", "default"]))
    if gw[0]:
        return gw
    try:
        with open("/proc/net/route") as f:
            return parse_proc_route(f.read())
    except OSError:
        return None, None


def local_ip_towards(target):
    """The local address the OS would use to reach target. Sends no packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def parse_ip_addr_prefix(text, ip):
    m = re.search(r"\binet " + re.escape(ip) + r"/(\d+)", text)
    return int(m.group(1)) if m else None


def parse_ip_addr_iface(text, ip):
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)\s+inet " + re.escape(ip) + r"/", line)
        if m:
            return m.group(1)
    return None


def parse_ifconfig_prefix(text, ip):
    m = re.search(r"inet " + re.escape(ip) + r"\s+netmask\s+(0x[0-9a-fA-F]+|" + IPV4_RE + r")", text)
    return mask_to_prefix(m.group(1)) if m else None


def parse_ifconfig_ether(text):
    m = re.search(r"\bether\s+(" + MAC_RE + r")", text)
    return norm_mac(m.group(1)) if m else None


def _ps_address_line(text, ip):
    return re.search(r"^\s*" + re.escape(ip) + r"/(\d+)(?:/(.*?))?\s*$", text, re.M)


def parse_ps_prefix(text, ip):
    """PowerShell lines 'address/prefix/adapter name' -> prefix length for ip."""
    m = _ps_address_line(text, ip)
    return int(m.group(1)) if m else None


def parse_ps_alias(text, ip):
    """... -> the adapter name (e.g. 'Wi-Fi' or 'Ethernet') that holds ip."""
    m = _ps_address_line(text, ip)
    return m.group(2).strip() if m and m.group(2) else None


def parse_ipconfig_prefix(text, ip):
    lines = text.splitlines()
    pattern = re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])")
    for i, line in enumerate(lines):
        if pattern.search(line):
            for nxt in lines[i + 1:i + 4]:
                m = re.search(r"(255\.\d{1,3}\.\d{1,3}\.\d{1,3})", nxt)
                if m:
                    return mask_to_prefix(m.group(1))
    return None


def linux_ioctl_prefix(iface):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            res = fcntl.ioctl(s.fileno(), 0x891B, struct.pack("256s", iface[:15].encode()))
        finally:
            s.close()
        return mask_to_prefix(socket.inet_ntoa(res[20:24]))
    except Exception:
        return None


def powershell(command, timeout=30):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout=timeout)


def get_prefix_len(local_ip, iface):
    """-> (network prefix length, adapter name if newly learned)."""
    if IS_LINUX:
        p = parse_ip_addr_prefix(run(["ip", "-o", "-4", "addr", "show"]), local_ip)
        if p is None and iface:
            p = linux_ioctl_prefix(iface)
        return p, None
    if IS_MAC:
        return parse_ifconfig_prefix(run(["ifconfig"]), local_ip), None
    if IS_WIN:
        out = powershell("Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object "
                         "{ $_.IPAddress + '/' + $_.PrefixLength + '/' + $_.InterfaceAlias }")
        p, alias = parse_ps_prefix(out, local_ip), parse_ps_alias(out, local_ip)
        if p is None:
            p = parse_ipconfig_prefix(run(["ipconfig"]), local_ip)
        return p, alias
    return None, None


def unique_ipv4(items, limit=3):
    seen, out = set(), []
    for item in items:
        if is_ipv4(item) and item not in seen and item != "0.0.0.0":
            seen.add(item)
            out.append(item)
    return out[:limit]


def get_dns_servers(local_ip):
    servers = []
    if IS_LINUX:
        try:
            with open("/etc/resolv.conf") as f:
                servers = re.findall(r"^\s*nameserver\s+(" + IPV4_RE + r")", f.read(), re.M)
        except OSError:
            servers = []
        if not servers or all(s.startswith("127.") for s in servers):
            found = re.findall(IPV4_RE, run(["resolvectl", "dns"]))
            servers = found + servers
    elif IS_MAC:
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(" + IPV4_RE + r")", run(["scutil", "--dns"]))
    elif IS_WIN:
        out = ""
        if local_ip and is_ipv4(local_ip):
            out = powershell(
                "Get-NetIPConfiguration | Where-Object { $_.IPv4Address.IPAddress -contains '%s' } "
                "| ForEach-Object { $_.DNSServer.ServerAddresses }" % local_ip)
        if not re.search(IPV4_RE, out):
            out = powershell("Get-DnsClientServerAddress -AddressFamily IPv4 | "
                             "ForEach-Object { $_.ServerAddresses }")
        servers = re.findall(IPV4_RE, out)
    return unique_ipv4(servers)


VPN_IFACE_RE = re.compile(r"^(tun|tap|wg|utun|ppp|ipsec|nordlynx|proton|tailscale|zt)", re.I)
WIN_VPN_ALIAS_RE = re.compile(r"vpn|wireguard|nordlynx|openvpn|tap-windows|proton|tailscale|zerotier|"
                              r"fortinet|anyconnect|wintun|globalprotect", re.I)


def looks_like_vpn(iface):
    if not iface:
        return False
    return bool(WIN_VPN_ALIAS_RE.search(iface)) if IS_WIN else bool(VPN_IFACE_RE.match(iface))


def get_network_basics():
    gateway, iface_or_ip = get_default_route()
    info = {"gateway": gateway, "interface": None, "local_ip": None,
            "prefix": None, "network": None, "dns_servers": [], "notes": []}
    if IS_WIN:
        info["local_ip"] = iface_or_ip if is_ipv4(iface_or_ip) else None
    else:
        info["interface"] = iface_or_ip
    if not info["local_ip"]:
        info["local_ip"] = local_ip_towards(gateway or "8.8.8.8")
    if IS_LINUX and info["local_ip"] and not info["interface"]:
        info["interface"] = parse_ip_addr_iface(run(["ip", "-o", "-4", "addr", "show"]), info["local_ip"])
    if info["local_ip"]:
        prefix, alias = safe("prefix", get_prefix_len, info["local_ip"], info["interface"]) or (None, None)
        info["prefix"] = prefix
        if alias and not info["interface"]:
            info["interface"] = alias  # Windows adapter name, e.g. "Wi-Fi" or "Ethernet"
        prefix = info["prefix"] if info["prefix"] is not None else 24
        if info["prefix"] is None:
            info["notes"].append("Could not read the network mask; assumed a standard home network (/24).")
        info["network"] = str(ipaddress.ip_network("%s/%d" % (info["local_ip"], prefix), strict=False))
    if looks_like_vpn(info["interface"]):
        info["notes"].append("Your internet traffic seems to go through a VPN (%s). Switch the VPN "
                             "off and run this again for accurate home-network results." % info["interface"])
    info["dns_servers"] = safe("dns servers", get_dns_servers, info["local_ip"]) or []
    if gateway is None:
        info["notes"].append("Could not find your router's address. Are you connected to a network?")
    return info


# --------------------------------------------------------------------------
# Wi-Fi connection details (per operating system)
# --------------------------------------------------------------------------

_KV_RE = re.compile(r"^\s*([^:]+?)\s*:\s?(.*?)\s*$")


def parse_netsh_interfaces(text):
    """Windows 'netsh wlan show interfaces'."""
    if not text.strip():
        return {"note": "Could not run 'netsh' to read Wi-Fi details."}
    if re.search(r"location permission|location services|access is denied", text, re.I) \
            and not re.search(r"^\s*SSID\s*:", text, re.M):
        return {"note": WIN_LOCATION_HINT}
    blocks, cur = [], None
    for line in text.splitlines():
        m = _KV_RE.match(line)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2).strip()
        if key == "name":
            cur = {}
            blocks.append(cur)
        if cur is not None:
            cur.setdefault(key, val)
    if not blocks:  # non-English Windows without a 'Name' label: treat as one block
        cur = {}
        for line in text.splitlines():
            m = _KV_RE.match(line)
            if m:
                cur.setdefault(m.group(1).strip().lower(), m.group(2).strip())
        blocks = [cur]
    block = next((b for b in blocks if b.get("ssid")), blocks[0])
    info = {
        "interface": block.get("name"),
        "ssid": block.get("ssid") or None,
        "bssid": norm_mac(block.get("ap bssid") or block.get("bssid")),
        "mac": norm_mac(block.get("physical address")),
        "standard": block.get("radio type"),
        "security": block.get("authentication"),
        "cipher": block.get("cipher"),
        "rx_rate": to_float(block.get("receive rate (mbps)")),
        "tx_rate": to_float(block.get("transmit rate (mbps)")),
        "channel": to_int(block.get("channel")),
        "band": normalize_band(block.get("band")),
        "signal_pct": to_int((block.get("signal") or "").rstrip("% ")),
        "rssi": to_int(block.get("rssi")),
    }
    # Fallbacks for non-English Windows: recognise values by their shape.
    for val in block.values():
        if info["signal_pct"] is None and re.match(r"^\d{1,3}\s*%$", val):
            info["signal_pct"] = to_int(val.rstrip("% "))
        if info["standard"] is None and re.match(r"^802\.11\w+$", val):
            info["standard"] = val
    return info


def parse_netsh_networks(text):
    """Windows 'netsh wlan show networks mode=bssid'."""
    nets, ssid, auth, cur = [], None, None, None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID \d+\s*:\s?(.*)$", line)
        if m:
            ssid, auth, cur = m.group(1).strip(), None, None
            continue
        m = _KV_RE.match(raw)
        if not m or ssid is None:
            continue
        key, val = m.group(1).strip().lower(), m.group(2).strip()
        if key == "authentication":
            auth = val
        elif re.match(r"^bssid \d+$", key):
            cur = {"ssid": ssid, "bssid": norm_mac(val), "security": auth}
            nets.append(cur)
        elif cur is not None:
            if key == "signal":
                cur["signal_pct"] = to_int(val.rstrip("% "))
            elif key == "channel":
                cur["channel"] = to_int(val)
            elif key == "band":
                cur["band"] = normalize_band(val)
            elif key == "radio type":
                cur["standard"] = val
    return nets


def _sp_indent(line):
    return len(line) - len(line.lstrip(" "))


def _sp_entries(lines, header_idx):
    """Children of a system_profiler section: [(name, {key: value})]."""
    base = _sp_indent(lines[header_idx])
    entries, child_indent = [], None
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        ind = _sp_indent(line)
        if ind <= base:
            break
        if child_indent is None:
            child_indent = ind
        stripped = line.strip()
        if ind == child_indent:
            entries.append((stripped[:-1] if stripped.endswith(":") else stripped, {}))
        elif ind > child_indent and entries:
            key, _, val = stripped.partition(":")
            entries[-1][1].setdefault(key.strip(), val.strip())
    return entries


def _sp_network(name, props):
    net = {"ssid": None if "redacted" in name.lower() else name,
           "standard": props.get("PHY Mode"),
           "security": props.get("Security"),
           "tx_rate": to_float(props.get("Transmit Rate")),
           "ssid_hidden_by_os": "redacted" in name.lower()}
    ch = re.match(r"\s*(\d+)\s*(?:\((\d+(?:\.\d+)?)\s*GHz(?:,\s*(\d+)\s*MHz)?)?", props.get("Channel", ""))
    if ch:
        net["channel"] = int(ch.group(1))
        net["band"] = normalize_band((ch.group(2) or "") + "GHz") if ch.group(2) else None
        if ch.group(3):
            net["width_mhz"] = int(ch.group(3))
    sn = re.search(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", props.get("Signal / Noise", ""))
    if sn:
        net["rssi"], net["noise"] = int(sn.group(1)), int(sn.group(2))
    return net


def parse_system_profiler(text):
    """macOS 'system_profiler SPAirPortDataType' -> (info, nearby)."""
    lines = text.splitlines()
    info, nearby = {}, []
    cur_idx = next((i for i, l in enumerate(lines) if l.strip() == "Current Network Information:"), None)
    if cur_idx is not None:
        base = _sp_indent(lines[cur_idx])
        for j in range(cur_idx - 1, -1, -1):
            stripped = lines[j].strip()
            if _sp_indent(lines[j]) < base and re.match(r"^[a-z]+\d+:$", stripped):
                info["interface"] = stripped[:-1]
                break
            if _sp_indent(lines[j]) == base and stripped.startswith("MAC Address:"):
                info["hw_mac"] = norm_mac(stripped.split(":", 1)[1])
        entries = _sp_entries(lines, cur_idx)
        if entries:
            info.update(_sp_network(*entries[0]))
            info["connected"] = True
    other_idx = next((i for i, l in enumerate(lines) if l.strip() == "Other Local Wi-Fi Networks:"), None)
    if other_idx is not None:
        nearby = [_sp_network(n, p) for n, p in _sp_entries(lines, other_idx)]
    return info, nearby


def _json_key(d, *fragments):
    """Value of the first key containing all fragments (Apple's JSON keys have long prefixes)."""
    for k, v in d.items():
        if all(f in k for f in fragments):
            return v
    return None


def _pretty_sp_security(value):
    """'spairport_security_mode_wpa2_personal' -> 'WPA2 Personal'."""
    if value in (None, ""):
        return None
    words = re.sub(r"^s?pairport_security_mode_", "", str(value)).replace("_", " ").split()
    return " ".join(w.upper() if re.match(r"^(wpa\d?|wep|owe|sae)$", w, re.I) else w.capitalize()
                    for w in words)


def _sp_json_network(entry):
    props = {"PHY Mode": _json_key(entry, "phymode"),
             "Channel": _json_key(entry, "channel"),
             "Security": _pretty_sp_security(_json_key(entry, "security")),
             "Signal / Noise": _json_key(entry, "signal_noise"),
             "Transmit Rate": _json_key(entry, "network_rate")}
    return _sp_network(str(entry.get("_name", "")), {k: str(v) for k, v in props.items() if v not in (None, "")})


def parse_system_profiler_json(text):
    """macOS 'system_profiler -json SPAirPortDataType'. Its keys stay in English whatever the
    Mac's language is, unlike the plain-text output. -> (info, nearby), or None if unreadable."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return None
    info, nearby = {}, []
    tops = data.get("SPAirPortDataType") if isinstance(data, dict) else None
    for top in tops if isinstance(tops, list) else []:
        if not isinstance(top, dict):
            continue
        ifaces = _json_key(top, "airport_interfaces")
        for iface in ifaces if isinstance(ifaces, list) else []:
            if not isinstance(iface, dict):
                continue
            cur = _json_key(iface, "current_network_information")
            if isinstance(cur, dict) and not info:
                info.update(_sp_json_network(cur))
                info["connected"] = True
                info["interface"] = iface.get("_name")
                mac = _json_key(iface, "mac_address")
                if mac:
                    info["hw_mac"] = norm_mac(str(mac))
            others = _json_key(iface, "other_local_wireless_networks")
            if isinstance(others, list) and not nearby:
                nearby = [_sp_json_network(o) for o in others if isinstance(o, dict)]
    return info, nearby


def parse_airport_info(text):
    """Older macOS 'airport -I'."""
    kv = {}
    for line in text.splitlines():
        key, sep, val = line.strip().partition(":")
        if sep:
            kv[key.strip()] = val.strip()
    if not kv.get("SSID") and not kv.get("BSSID"):
        return {}
    info = {"ssid": kv.get("SSID") or None, "bssid": norm_mac(kv.get("BSSID")),
            "rssi": to_int(kv.get("agrCtlRSSI")), "noise": to_int(kv.get("agrCtlNoise")),
            "tx_rate": to_float(kv.get("lastTxRate")), "security": kv.get("link auth"),
            "connected": True}
    ch = re.match(r"\s*(\d+)", kv.get("channel", ""))
    if ch:
        info["channel"] = int(ch.group(1))
    return info


def parse_iw_link(text):
    """Linux 'iw dev <iface> link'."""
    if not text.strip() or text.strip().lower().startswith("not connected"):
        return {}
    info = {}
    m = re.search(r"Connected to (" + MAC_RE + r")", text)
    if m:
        info["bssid"] = norm_mac(m.group(1))
    m = re.search(r"^\s*SSID:\s*(.*)$", text, re.M)
    if m:
        info["ssid"] = m.group(1).strip() or None
    m = re.search(r"freq:\s*(\d+(?:\.\d+)?)", text)
    if m:
        info["channel"], info["band"] = freq_to_channel(int(float(m.group(1))))
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", text)
    if m:
        info["rssi"] = int(m.group(1))
    for key, label in (("rx_rate", "rx"), ("tx_rate", "tx")):
        m = re.search(r"^\s*" + label + r" bitrate:\s*([\d.]+)\s*MBit/s(.*)$", text, re.M)
        if m:
            info[key] = float(m.group(1))
            rest = m.group(2)
            if "standard" not in info:
                for marker, std in (("EHT-MCS", "802.11be"), ("HE-MCS", "802.11ax"),
                                    ("VHT-MCS", "802.11ac"), ("MCS", "802.11n")):
                    if marker in rest:
                        info["standard"] = std
                        break
            w = re.search(r"(\d+)MHz", rest)
            if w and "width_mhz" not in info:
                info["width_mhz"] = int(w.group(1))
    if info:
        info["connected"] = True
    return info


def nm_pct_to_dbm(pct, connected):
    """NetworkManager's own % scales (from its nm-wifi-utils code): for the connected network
    30..100 % means -90..-20 dBm; for other networks 0..100 % means -100..-40 dBm."""
    if connected:
        return int(round(max(30, min(100, pct)) - 120))
    return int(round(-40 - (100 - max(0, min(100, pct))) * 0.6))


def parse_nmcli_wifi(text):
    """Linux 'nmcli -t -f IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list'."""
    nets = []
    for line in text.splitlines():
        parts = [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 8:
            continue
        in_use, ssid, bssid, chan, freq, _rate, signal, security = parts[:8]
        net = {"in_use": in_use.strip() == "*", "ssid": ssid or "", "bssid": norm_mac(bssid),
               "signal_pct": to_int(signal),
               "security": security.strip() if security.strip() not in ("", "--") else "Open"}
        if net["signal_pct"] is not None:
            net["rssi"] = nm_pct_to_dbm(net["signal_pct"], net["in_use"])
            net["rssi_estimated"] = True
        f = re.match(r"\s*(\d+)", freq)
        ch, band = freq_to_channel(int(f.group(1))) if f else (None, None)
        net["channel"] = ch if ch is not None else to_int(chan)
        net["band"] = band
        nets.append(net)
    return nets


def parse_proc_wireless(text, iface):
    for line in text.splitlines():
        m = re.match(r"\s*(\S+):\s+\S+\s+(-?[\d.]+)\.?\s+(-?[\d.]+)\.?\s+(-?[\d.]+)", line)
        if m and m.group(1) == iface:
            level = to_float(m.group(3))
            if level is not None and level < 0:
                return int(level)
    return None


def linux_wifi_iface():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return None
    wifi = [n for n in names if os.path.isdir("/sys/class/net/%s/wireless" % n)
            or os.path.exists("/sys/class/net/%s/phy80211" % n)]

    def is_up(n):
        try:
            with open("/sys/class/net/%s/operstate" % n) as f:
                return f.read().strip() == "up"
        except OSError:
            return False
    wifi.sort(key=lambda n: not is_up(n))
    return wifi[0] if wifi else None


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def get_wifi_info():
    """-> (info about this computer's Wi-Fi connection, list of nearby networks)."""
    info, nearby = {}, []
    if IS_WIN:
        info = parse_netsh_interfaces(run(["netsh", "wlan", "show", "interfaces"]))
        if not info.get("note"):
            nearby = parse_netsh_networks(run(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    elif IS_MAC:
        parsed = parse_system_profiler_json(run(["system_profiler", "-json", "SPAirPortDataType"], timeout=60))
        if parsed and (parsed[0] or parsed[1]):
            info, nearby = parsed
        else:  # older macOS without -json, or an unexpected layout: read the text version
            info, nearby = parse_system_profiler(run(["system_profiler", "SPAirPortDataType"], timeout=60))
        if not info.get("connected") and os.path.exists(AIRPORT_CMD):
            info.update(parse_airport_info(run([AIRPORT_CMD, "-I"])))
        iface = info.get("interface")
        if not iface:
            m = re.search(r"Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: (\S+)",
                          run(["networksetup", "-listallhardwareports"]))
            iface = m.group(1) if m else None
            info["interface"] = iface
        if iface:
            info["mac"] = parse_ifconfig_ether(run(["ifconfig", iface])) or info.get("hw_mac")
        if info.get("ssid_hidden_by_os"):
            info["note"] = MAC_LOCATION_HINT
    elif IS_LINUX:
        iface = linux_wifi_iface()
        info["interface"] = iface
        if iface:
            for iw in ("iw", "/usr/sbin/iw", "/sbin/iw"):  # older Debian keeps iw off the user's PATH
                link = run([iw, "dev", iface, "link"])
                if link.strip():
                    info.update(parse_iw_link(link))
                    break
            info["mac"] = norm_mac(read_file("/sys/class/net/%s/address" % iface))
            if info.get("rssi") is None:  # a real dBm reading beats NetworkManager's percentage
                rssi = parse_proc_wireless(read_file("/proc/net/wireless"), iface)
                if rssi is not None:
                    info["rssi"] = rssi
                    info["connected"] = True
        nm = parse_nmcli_wifi(run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                                   "dev", "wifi", "list"], english=False, timeout=30))
        active = [n for n in nm if n["in_use"]]
        if info.get("bssid"):
            active = [n for n in active if n.get("bssid") == info["bssid"]] or active
        if active:
            a = active[0]
            if info.get("rssi") is None and a.get("rssi") is not None:
                info["rssi"], info["rssi_estimated"] = a["rssi"], True
            for key in ("ssid", "bssid", "channel", "band", "signal_pct", "security"):
                if info.get(key) in (None, "") and a.get(key) not in (None, ""):
                    info[key] = a[key]
            info["connected"] = True
        nearby = [n for n in nm if not n["in_use"]]
    finalize_wifi(info)
    for n in nearby:
        finalize_wifi(n)
    return info, nearby


def finalize_wifi(info):
    """Fill in derived fields (estimated dBm, band, generation, security level)."""
    if info.get("rssi") is None and info.get("signal_pct") is not None:
        info["rssi"] = pct_to_dbm(info["signal_pct"])
        info["rssi_estimated"] = True
    if not info.get("band") and info.get("channel"):
        info["band"] = band_from_channel(info["channel"])
    info["generation"] = wifi_generation(info.get("standard"), info.get("band"))
    info["security_level"], info["security_label"] = classify_security(info.get("security"), info.get("cipher"))
    if "connected" not in info:
        info["connected"] = bool(info.get("ssid") or info.get("bssid"))
    return info


def analyze_channels(wifi, nearby):
    """How crowded is the channel this computer uses, and which 2.4 GHz channel is quietest?"""
    own_ssid, own_bssid = wifi.get("ssid"), wifi.get("bssid")
    others = [n for n in nearby if n.get("channel")
              and not (own_bssid and n.get("bssid") == own_bssid)
              and not (own_ssid and n.get("ssid") == own_ssid)]

    def weight(n):
        r = n.get("rssi")
        if r is None:
            return 1.0
        return 2.0 if r >= -60 else 1.0 if r >= -75 else 0.3

    result = {"networks_seen": len(nearby), "own_on_other_bands": sorted(
        {n["band"] for n in nearby if own_ssid and n.get("ssid") == own_ssid and n.get("band")
         and n.get("band") != wifi.get("band")})}
    nets24 = [n for n in others if n.get("band") == "2.4 GHz"]
    scores = {}
    for c in (1, 6, 11):
        scores[c] = round(sum(weight(n) for n in nets24 if abs(n["channel"] - c) <= 4), 1)
    result["scores_24"] = scores
    result["counts_24"] = {c: sum(1 for n in nets24 if abs(n["channel"] - c) <= 4) for c in (1, 6, 11)}
    if nets24:
        result["best_24"] = min(scores, key=lambda c: (scores[c], c))
    ch, band = wifi.get("channel"), wifi.get("band")
    if ch and band:
        if band == "2.4 GHz":
            result["overlapping"] = sum(1 for n in nets24 if abs(n["channel"] - ch) <= 4)
            result["own_score"] = round(sum(weight(n) for n in nets24 if abs(n["channel"] - ch) <= 4), 1)
        else:
            same = [n for n in others if n.get("band") == band and n["channel"] == ch]
            result["same_channel"] = len(same)
            result["same_channel_strong"] = sum(1 for n in same if (n.get("rssi") or -100) >= -70)
    return result


# --------------------------------------------------------------------------
# Response times (ping) and DNS speed
# --------------------------------------------------------------------------

_PING_TIME = re.compile(r"([=<])\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)


def parse_ping_times(text):
    """Reply times in ms from ping output (any OS; works with translated Windows ping too)."""
    times = []
    for line in text.splitlines():
        low = line.lower()
        if "ttl" not in low or "dup" in low:
            continue
        m = _PING_TIME.search(line)
        if m:
            value = to_float(m.group(2))
            if value is None:
                continue
            times.append(value / 2.0 if m.group(1) == "<" else value)
    return times


def ping_cmd(host, count, timeout_ms):
    if IS_WIN:
        return ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    if IS_MAC:  # macOS: -W is in milliseconds, -t is an overall limit in seconds
        return ["ping", "-c", str(count), "-W", str(timeout_ms),
                "-t", str(int(count * (1 + timeout_ms / 1000.0)) + 2), host]
    return ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), host]


def summarize_times(times, sent):
    received = min(len(times), sent)
    stats = {"sent": sent, "received": received,
             "loss_pct": round(100.0 * (sent - received) / sent, 1) if sent else None}
    if times:
        stats.update(median_ms=round(statistics.median(times), 1), min_ms=round(min(times), 1),
                     max_ms=round(max(times), 1), avg_ms=round(statistics.mean(times), 1),
                     jitter_ms=round(statistics.mean(abs(a - b) for a, b in zip(times, times[1:])), 1)
                     if len(times) > 1 else 0.0)
    return stats


def _tcp_connect_ms(host, port, timeout):
    """Time to set up a TCP connection, in ms (None if no answer at all)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except ConnectionRefusedError:
        pass  # a refusal is still an answer from the device
    except OSError:
        return None
    return (time.perf_counter() - t0) * 1000


def tcp_rtt_stats(host, ports, count):
    """Fallback when 'ping' is missing or blocked: time TCP connection set-up."""
    port = next((p for p in ports if _tcp_connect_ms(host, p, 1.5) is not None), None)
    times = []
    if port is not None:
        for _ in range(count):
            ms = _tcp_connect_ms(host, port, 2.0)
            if ms is not None:
                times.append(ms)
            time.sleep(0.2)
    stats = summarize_times(times, count)
    stats["method"] = "tcp"
    return stats


def ping_stats(host, count=20, timeout_ms=1000, tcp_ports=(443, 80)):
    out = run(ping_cmd(host, count, timeout_ms), timeout=count * (timeout_ms / 1000.0 + 1) + 15)
    if out.strip():
        times = parse_ping_times(out)
        if times:
            stats = summarize_times(times, count)
            stats["method"] = "ping"
            return stats
    # ping missing, or every ping blocked: try TCP so we still learn something
    stats = tcp_rtt_stats(host, tcp_ports, max(5, count // 2))
    if stats["received"] == 0 and out.strip():
        stats = summarize_times([], count)
        stats["method"] = "ping"
    return stats


def build_dns_query(name, qtype=1, recursion=True, tid=None):
    tid = random.randint(0, 0xFFFF) if tid is None else tid
    packet = struct.pack(">HHHHHH", tid, 0x0100 if recursion else 0, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        packet += bytes([len(raw)]) + raw
    return tid, packet + b"\x00" + struct.pack(">HH", qtype, 1)


def read_dns_name(msg, offset):
    labels, end, hops = [], None, 0
    while True:
        if offset >= len(msg):
            raise ValueError("truncated name")
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("truncated pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            hops += 1
            if hops > 30:
                raise ValueError("pointer loop")
            continue
        offset += 1
        labels.append(msg[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def parse_dns_message(msg):
    tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = read_dns_name(msg, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        _, offset = read_dns_name(msg, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", msg[offset:offset + 10])
        offset += 10
        start = offset
        offset += rdlen
        if rtype == 12:
            answers.append(("PTR", read_dns_name(msg, start)[0]))
        elif rtype == 1 and rdlen == 4:
            answers.append(("A", socket.inet_ntoa(msg[start:start + 4])))
        else:
            answers.append((rtype, None))
    return {"id": tid, "rcode": flags & 0xF, "answers": answers}


def udp_request(host, port, packet, timeout):
    """Send one UDP packet, wait for the reply whose first 2 bytes (the ID) match."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        t0 = time.perf_counter()
        deadline = t0 + timeout
        s.sendto(packet, (host, port))
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None, None
            s.settimeout(remaining)
            data, _addr = s.recvfrom(4096)
            if len(data) >= 12 and data[:2] == packet[:2]:
                return (time.perf_counter() - t0) * 1000, data
    except OSError:
        return None, None
    finally:
        s.close()


def dns_query(server, name, qtype=1, port=53, timeout=2.0, recursion=True):
    _tid, packet = build_dns_query(name, qtype, recursion)
    ms, data = udp_request(server, port, packet, timeout)
    if data is None:
        return None, None
    try:
        return ms, parse_dns_message(data)
    except (ValueError, struct.error, OSError):
        return ms, None


def dns_server_speed(server, names):
    times, failures = [], 0
    for name in names:
        ms, parsed = dns_query(server, name)
        if ms is not None and parsed is not None and parsed["rcode"] == 0:
            times.append(ms)
        else:
            failures += 1
    return {"median_ms": round(statistics.median(times), 1) if times else None,
            "answered": len(times), "failed": failures}


def measure_dns(gateway, system_servers):
    candidates = []
    for s in system_servers:
        candidates.append((s, "Your current DNS" + (" (your router)" if s == gateway else ""), "current"))
    if gateway and gateway not in system_servers:
        candidates.append((gateway, "Your router", "router"))
    for ip, label in PUBLIC_DNS:
        if ip not in [c[0] for c in candidates]:
            candidates.append((ip, label, "public"))
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates) or 1) as pool:
        futures = {pool.submit(dns_server_speed, ip, DNS_TEST_NAMES): (ip, label, role)
                   for ip, label, role in candidates}
        for fut, (ip, label, role) in futures.items():
            res = safe("dns " + ip, fut.result) or {"median_ms": None, "answered": 0, "failed": 0}
            if role == "router" and not res["answered"]:
                continue  # this router simply doesn't offer DNS; nothing to report
            res.update(ip=ip, label=label, role=role)
            results.append(res)
    return results


def measure_latency_and_dns(basics, count):
    gateway = basics.get("gateway")
    latency, dns = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {}
        if gateway:
            jobs["router"] = pool.submit(ping_stats, gateway, count, 1000, (80, 443, 53))
        for ip, label in PUBLIC_PING_TARGETS:
            jobs[label] = pool.submit(ping_stats, ip, count)
        dns_job = pool.submit(measure_dns, gateway, basics.get("dns_servers") or [])
        for key, fut in jobs.items():
            res = safe("ping " + key, fut.result)
            if res:
                res["host"] = gateway if key == "router" else dict((l, i) for i, l in PUBLIC_PING_TARGETS)[key]
                latency[key] = res
        dns = safe("dns", dns_job.result) or []
    internet = [latency[l] for _, l in PUBLIC_PING_TARGETS if latency.get(l, {}).get("received")]
    if internet:
        best = min(internet, key=lambda s: (s["loss_pct"], s["median_ms"]))
        latency["internet"] = dict(best, label=next(l for _, l in PUBLIC_PING_TARGETS if latency.get(l) is best))
    return latency, dns


# --------------------------------------------------------------------------
# Devices on the network
# --------------------------------------------------------------------------

def parse_neighbor_table(text):
    """ARP / neighbour tables from Linux, macOS or Windows -> [(ip, mac)]."""
    pairs = []
    for line in text.splitlines():
        if "incomplete" in line.lower():
            continue
        ip = re.search(r"(?<![\d.])(" + IPV4_RE + r")(?![\d.])", line)
        mac = re.search(MAC_RE, line)
        if ip and mac:
            m = norm_mac(mac.group(0))
            if m and is_unicast_mac(m) and is_ipv4(ip.group(1)):
                pairs.append((ip.group(1), m))
    return pairs


def read_neighbor_table():
    if IS_LINUX:
        text = read_file("/proc/net/arp")
        return parse_neighbor_table(text) if text else parse_neighbor_table(run(["ip", "-4", "neigh"]))
    if IS_MAC:
        return parse_neighbor_table(run(["arp", "-an"]))
    if IS_WIN:
        return parse_neighbor_table(run(["arp", "-a"]))
    return []


def udp_poke(hosts):
    """Send an empty UDP packet to each address. This makes the computer look up every
    device's hardware address (ARP), so devices that ignore ping still show up."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i, host in enumerate(hosts):
            try:
                s.sendto(b"", (host, 9))  # port 9 = 'discard'
            except OSError:
                pass
            if i % 32 == 31:
                time.sleep(0.02)
    finally:
        s.close()


def ping_once(host):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "800", host]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", "800", "-t", "2", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
    return bool(parse_ping_times(run(cmd, timeout=6)))


def ping_sweep(hosts, workers=48):
    alive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ok in zip(hosts, pool.map(ping_once, hosts)):
            if ok:
                alive.add(host)
    return alive


def reverse_name(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def mdns_name(ip, timeout=1.5):
    """Ask the device itself for its name (Apple devices, many printers, Linux, Android TV...)."""
    _ms, parsed = dns_query(ip, reverse_name(ip), qtype=12, port=5353, timeout=timeout, recursion=False)
    if parsed:
        for rtype, value in parsed["answers"]:
            if rtype == "PTR" and value:
                return value.rstrip(".")
    return None


NBSTAT_NAME = b"\x20" + b"CK" + b"A" * 30 + b"\x00"


def parse_nbstat(data):
    """Windows-style (NetBIOS) node status reply -> computer name."""
    try:
        _, offset = read_dns_name(data, 12)
        offset += 8  # type, class, ttl
        offset += 2  # rdlength
        count = data[offset]
        offset += 1
        for _ in range(count):
            entry = data[offset:offset + 18]
            if len(entry) < 18:
                break
            name = entry[:15].decode("ascii", "replace").strip("\x00 ").strip()
            suffix = entry[15]
            flags = struct.unpack(">H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000 and name and name != "*":
                return name
            offset += 18
    except (IndexError, ValueError, struct.error):
        return None
    return None


def netbios_name(ip, timeout=1.5):
    tid = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + NBSTAT_NAME + struct.pack(">HH", 0x21, 1)
    _ms, data = udp_request(ip, 137, packet, timeout)
    return parse_nbstat(data) if data else None


def run_with_deadline(tasks, seconds):
    """Run (fn, args) tasks in background threads; give up waiting after `seconds`."""
    threads = []
    for fn, args in tasks:
        t = threading.Thread(target=fn, args=args, daemon=True)
        t.start()
        threads.append(t)
    deadline = time.monotonic() + seconds
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))


def resolve_names(ips, seconds=5.0):
    names = {ip: {} for ip in ips}
    lock = threading.Lock()

    def store(ip, key, value):
        if value and value != ip:
            with lock:
                names[ip][key] = clean_text(value.rstrip("."), 80)

    def rdns(ip):
        try:
            store(ip, "dns", socket.gethostbyaddr(ip)[0])
        except (OSError, UnicodeError):
            pass

    def mdns(ip):
        store(ip, "mdns", mdns_name(ip))

    def nb(ip):
        store(ip, "netbios", netbios_name(ip))

    tasks = [(fn, (ip,)) for ip in ips for fn in (rdns, mdns, nb)]
    for i in range(0, len(tasks), 150):  # don't open too many sockets at once
        run_with_deadline(tasks[i:i + 150], seconds)
    with lock:
        return {ip: dict(v) for ip, v in names.items()}


def parse_ssdp_response(data):
    text = data.decode("latin-1", "replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0].upper().startswith(("HTTP/1.1 200", "NOTIFY")):
        return None
    headers = {}
    for line in lines[1:]:
        key, sep, val = line.partition(":")
        if sep:
            headers[key.strip().upper()] = val.strip()
    return headers


def ssdp_discover(local_ip, wait=3.0):
    """Ask UPnP devices (routers, TVs, speakers, printers...) to announce themselves."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode("ascii")
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.bind((local_ip, 0))
        except OSError:
            s.bind(("", 0))
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
            time.sleep(0.1)
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            s.settimeout(remaining)
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                break
            headers = parse_ssdp_response(data)
            if headers is not None:
                found.setdefault(addr[0], []).append(headers)
    except OSError:
        pass
    finally:
        s.close()
    return found


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# Requests to devices at home must never go through a proxy, and are never redirected.
LAN_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def lan_http_get(url, timeout=3.0, limit=65536):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with LAN_OPENER.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read(limit)
    except urllib.error.HTTPError as err:
        try:
            body = err.read(limit)
        except Exception:
            body = b""
        return err.code, dict(err.headers.items()) if err.headers else {}, body
    except Exception:
        return None, {}, b""


def parse_upnp_description(xml_bytes):
    text = xml_bytes.decode("utf-8", "replace")
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
        m = re.search(r"<%s>\s*(.*?)\s*</%s>" % (tag, tag), text, re.S | re.I)
        if m and m.group(1).strip():
            out[tag] = clean_text(m.group(1), 80)
    return out


def describe_upnp_devices(ssdp):
    """Fetch each device's own description (only from the device that answered)."""
    info = {}
    lock = threading.Lock()

    def fetch(ip, location):
        status, _headers, body = lan_http_get(location, timeout=2.5)
        if status == 200 and body:
            desc = parse_upnp_description(body)
            if desc:
                with lock:
                    info.setdefault(ip, desc)

    tasks = []
    for ip, responses in ssdp.items():
        locations = []
        for h in responses:
            loc = h.get("LOCATION", "")
            m = re.match(r"^http://([^/:]+)(?::\d+)?/", loc)
            if m and m.group(1) == ip and loc not in locations:
                locations.append(loc)
        for loc in locations[:2]:
            tasks.append((fetch, (ip, loc)))
    run_with_deadline(tasks, 6.0)
    for ip, responses in ssdp.items():
        d = info.setdefault(ip, {})
        types = " ".join(h.get("ST", "") + " " + h.get("NT", "") for h in responses)
        d["is_gateway_device"] = "InternetGatewayDevice" in types or \
            "InternetGatewayDevice" in d.get("deviceType", "")
        servers = [h.get("SERVER") for h in responses if h.get("SERVER")]
        if servers:
            d["server"] = clean_text(servers[0], 80)
    return info


def tcp_port_open(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


ROUTER_PORTS = [(21, "FTP file sharing"), (22, "SSH"), (23, "Telnet"), (80, "web admin page"),
                (443, "secure web admin page"), (445, "Windows file sharing (SMB)"),
                (8080, "web (alternate)"), (8443, "secure web (alternate)")]


def check_router(gateway):
    info = {"ip": gateway}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ROUTER_PORTS)) as pool:
        states = list(pool.map(lambda p: tcp_port_open(gateway, p[0]), ROUTER_PORTS))
    info["open_ports"] = [{"port": p, "service": name} for (p, name), ok in zip(ROUTER_PORTS, states) if ok]
    open_set = {p["port"] for p in info["open_ports"]}
    if 80 in open_set:
        status, headers, body = lan_http_get("http://%s/" % gateway)
        page = {"status": status}
        if headers:
            hdr = {k.lower(): v for k, v in headers.items()}
            if hdr.get("server"):
                page["server"] = clean_text(hdr["server"])
            if hdr.get("location"):
                page["redirects_to"] = clean_text(hdr["location"], 100)
        m = re.search(rb"<title[^>]*>(.*?)</title>", body or b"", re.I | re.S)
        if m:
            page["title"] = clean_text(m.group(1).decode("utf-8", "replace"))
        info["web"] = page
    info["admin_url"] = ("http://%s" % gateway) if 80 in open_set else \
        ("https://%s" % gateway) if 443 in open_set else ("http://%s" % gateway)
    return info


def scan_hosts(network, local_ip):
    net = ipaddress.ip_network(network, strict=False)
    note = None
    if net.prefixlen < 24:
        note = ("Your network is larger than usual (%s); the 254 addresses around this computer "
                "were scanned. Devices elsewhere still appear if they recently talked to it." % network)
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
    return [str(h) for h in net.hosts() if str(h) != local_ip], note


def wifi_carries_traffic(basics, wifi):
    """Is the Wi-Fi adapter the one the internet traffic actually uses?
    False for a laptop that is also plugged in by cable. None when it can't be told."""
    if not wifi.get("connected"):
        return False
    route_iface, wifi_iface = basics.get("interface"), wifi.get("interface")
    if route_iface and wifi_iface:
        return route_iface.lower() == wifi_iface.lower()
    return None


def get_self_mac(basics, wifi):
    """This computer's hardware address on the home network (None if unknown)."""
    if wifi.get("connected") and wifi.get("mac") and wifi.get("carries_traffic") is not False:
        return wifi["mac"]
    iface = basics.get("interface")
    if iface and IS_LINUX:
        return norm_mac(read_file("/sys/class/net/%s/address" % iface))
    if iface and IS_MAC:
        return parse_ifconfig_ether(run(["ifconfig", iface]))
    return wifi.get("mac")


def scan_devices(basics, wifi):
    local_ip, network, gateway = basics.get("local_ip"), basics.get("network"), basics.get("gateway")
    if not local_ip or not network:
        return {"skipped": "Could not work out your local network, so the device scan was skipped."}
    if not ipaddress.ip_address(local_ip).is_private:
        return {"skipped": "This computer's address (%s) isn't a home-network address, so the device "
                           "scan was skipped. This happens with some VPNs and mobile hotspots." % local_ip}
    hosts, note = scan_hosts(network, local_ip)
    net = ipaddress.ip_network(network, strict=False)
    udp_poke(hosts)
    alive = ping_sweep(hosts)
    time.sleep(0.5)
    seen = dict((ip, mac) for ip, mac in read_neighbor_table())
    missing = [h for h in hosts if h not in seen]
    if missing:
        udp_poke(missing)
        time.sleep(1.5)
        seen.update(dict(read_neighbor_table()))
    devices = {}
    for ip, mac in seen.items():
        addr = ipaddress.ip_address(ip)
        if addr in net and addr not in (net.network_address, net.broadcast_address) and ip != local_ip:
            devices[ip] = {"ip": ip, "mac": mac}
    for ip in alive:
        devices.setdefault(ip, {"ip": ip, "mac": None})
    devices[local_ip] = {"ip": local_ip, "mac": get_self_mac(basics, wifi), "is_this_computer": True}
    for ip, d in devices.items():
        d["responds_to_ping"] = ip in alive
        d["random_mac"] = is_random_mac(d["mac"]) if d.get("mac") else False
        d["is_router"] = ip == gateway
    others = [ip for ip in devices if ip != local_ip]
    names = safe("names", resolve_names, others) or {}
    ssdp = safe("ssdp", ssdp_discover, local_ip) or {}
    upnp = safe("upnp", describe_upnp_devices, ssdp) or {}
    for ip, d in devices.items():
        d["names"] = names.get(ip, {})
        if ip in upnp:
            d["upnp"] = upnp[ip]
    return {"devices": sorted(devices.values(), key=lambda d: ipaddress.ip_address(d["ip"])),
            "scanned": len(hosts), "note": note}


def display_name(d):
    if d.get("label"):
        return d["label"]
    if d.get("is_this_computer"):
        return "This computer"
    upnp = d.get("upnp") or {}
    model = " ".join(x for x in (upnp.get("manufacturer"), upnp.get("modelName")) if x)
    for key in ("mdns", "netbios", "dns"):
        name = (d.get("names") or {}).get(key)
        if name:
            return re.sub(r"\.(local|lan|home|localdomain|home\.arpa)$", "", name, flags=re.I)
    if upnp.get("friendlyName"):
        return upnp["friendlyName"]
    if model:
        return model
    if d.get("vendor"):
        return "(made by %s)" % d["vendor"]
    return "(no name given)"


# --------------------------------------------------------------------------
# Remembering devices between runs
# --------------------------------------------------------------------------

def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_json(path, data):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, str(path))


def update_known_devices(path, network_key, devices, labels, now):
    db = load_json(path)
    if not isinstance(db, dict) or not isinstance(db.get("networks"), dict):
        db = {"about": "Devices seen by wifi_checkup.py. You can type a name for each device in "
                       "its \"name\" field, or use: --name <MAC address> \"Mum's phone\"",
              "networks": {}}
    net = db["networks"].setdefault(network_key, {"first_scan": now, "devices": {}})
    known = net.setdefault("devices", {})
    first_run = not known
    for mac, name in labels.items():
        known.setdefault(mac, {"first_seen": now})["name"] = name
    for d in devices:
        mac = d.get("mac")
        if not mac:
            d["status"] = "you" if d.get("is_this_computer") else "?"
            continue
        rec = known.get(mac)
        if rec is None or "last_seen" not in rec:
            if first_run:
                d["status"] = "first scan"
            else:  # a device the person has already named isn't a stranger
                d["status"] = "known" if rec and rec.get("name") else "NEW"
            rec = known.setdefault(mac, {"first_seen": now})
        else:
            d["status"] = "known"
        if d.get("is_this_computer"):
            d["status"] = "you"
        elif d.get("is_router"):
            d["status"] = "router"
        rec["last_seen"] = now
        rec["last_ip"] = d["ip"]
        rec.setdefault("name", "")
        rec["seen_as"] = display_name(dict(d, label=None))
        if d.get("vendor"):
            rec["vendor"] = d["vendor"]
        d["label"] = rec.get("name") or ""
        d["previously_seen"] = rec.get("first_seen")
    net["last_scan"] = now
    save_json(path, db)
    return first_run, db


def lookup_vendors(devices, cache, limit=40):
    """Optional (--vendors): ask api.macvendors.com who made each device.
    Only the first half of each address (the maker's code) is sent."""
    looked = 0
    for d in devices:
        mac = d.get("mac")
        if not mac or d.get("random_mac"):
            continue
        oui = mac[:8]
        if oui not in cache and looked < limit:
            looked += 1
            try:
                req = urllib.request.Request("https://api.macvendors.com/" + oui.replace(":", "-"),
                                             headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    cache[oui] = clean_text(resp.read(200).decode("utf-8", "replace"), 40)
            except urllib.error.HTTPError as err:
                if err.code == 404:
                    cache[oui] = ""
            except Exception:
                pass
            time.sleep(1.1)  # the free service allows about one lookup per second
        if cache.get(oui):
            d["vendor"] = cache[oui]


# --------------------------------------------------------------------------
# Internet speed test
# --------------------------------------------------------------------------

class _Counter:
    def __init__(self):
        self._n = 0
        self._lock = threading.Lock()

    def add(self, k):
        with self._lock:
            self._n += k

    @property
    def value(self):
        with self._lock:
            return self._n


class _StopTransfer(Exception):
    pass


class _UploadBody:
    """Upload data that stops the transfer as soon as the time is up."""

    def __init__(self, size, block, deadline, sent_counter):
        self.left, self.block, self.deadline, self.sent = size, block, deadline, sent_counter

    def read(self, n=-1):
        if self.left <= 0:
            return b""  # fully sent: let this piece finish even if time is now up
        if time.perf_counter() >= self.deadline:
            raise _StopTransfer()
        if n is None or n < 0:
            n = self.left
        n = min(n, self.left, len(self.block))
        self.left -= n
        self.sent.add(n)
        return self.block[:n]


def _was_stopped(exc):
    return isinstance(exc, _StopTransfer) or isinstance(getattr(exc, "reason", None), _StopTransfer) \
        or isinstance(exc.__context__, _StopTransfer)


def _http(url, data=None, timeout=15, headers=None):
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST" if data is not None else "GET")
    return urllib.request.urlopen(req, timeout=timeout)


def _note_error(errors, exc):
    errors.append("%s: %s" % (type(exc).__name__, str(exc)[:160]))


def download_worker(base, deadline, counter, errors):
    while time.perf_counter() < deadline and len(errors) < 30:
        try:
            with _http("%s/__down?bytes=%d" % (base, DOWNLOAD_REQUEST_BYTES)) as resp:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    counter.add(len(chunk))
                    if time.perf_counter() >= deadline:
                        return
        except Exception as exc:
            _note_error(errors, exc)
            time.sleep(0.5)


def _upload_piece(base, size, block, deadline, sent):
    """Upload `size` bytes; return the seconds until the server confirmed it had them all."""
    body = _UploadBody(size, block, deadline, sent)
    started = time.perf_counter()
    with _http(base + "/__up", data=body, timeout=30,
               headers={"Content-Type": "application/octet-stream", "Content-Length": str(size)}) as resp:
        resp.read()
    return time.perf_counter() - started


def upload_worker(base, deadline, done, sent, errors):
    """Upload in pieces; each piece is timed until the server confirms it has all of it.
    (Counting bytes as they leave would be misleading: the computer's own network
    buffers swallow a second or more of data before anything reaches the internet.)"""
    block = os.urandom(1 << 16)  # random data, so nothing can compress it
    # Every piece also pays a fixed cost - setting up the connection and waiting one round
    # trip for the reply. Measure it with tiny uploads and take it off each piece's time,
    # so high-latency links (satellite, some mobile) aren't reported as slower than they are.
    overhead = None
    for _ in range(2):
        try:
            took = _upload_piece(base, 1, block, deadline, sent)
            overhead = took if overhead is None else min(overhead, took)
        except Exception as exc:
            if _was_stopped(exc):
                return
            _note_error(errors, exc)
    overhead = overhead or 0.0
    size = 250_000
    while time.perf_counter() < deadline and len(errors) < 30:
        try:
            took = _upload_piece(base, size, block, deadline, sent)
        except Exception as exc:
            if _was_stopped(exc):
                return
            _note_error(errors, exc)
            time.sleep(0.5)
            continue
        if took - overhead >= 0.25:
            done.append((took - overhead, size))
        if took < max(1.5, 3 * overhead):  # aim for pieces that take a couple of seconds
            size = min(size * 2, 64_000_000)


def upload_rate(per_stream):
    """Mbps from each connection's completed uploads [(seconds, bytes)], added up."""
    total = 0.0
    for uploads in per_stream:
        if not uploads:
            continue
        # quick small pieces mostly measure connection set-up, so leave them out
        longer = [u for u in uploads if u[0] >= 0.5] or [max(uploads, key=lambda u: u[1])]
        seconds, size = sum(u[0] for u in longer), sum(u[1] for u in longer)
        if seconds > 0:
            total += size * 8 / seconds / 1e6
    return round(total, 1) if total else None


def measure_upload(base, seconds, streams, warmup=0.0, during=None):
    t0 = time.perf_counter()
    deadline = t0 + seconds
    sent, errors = _Counter(), []
    per_stream = [[] for _ in range(streams)]
    threads = [threading.Thread(target=upload_worker, args=(base, deadline, per_stream[i], sent, errors),
                                daemon=True) for i in range(streams)]
    for t in threads:
        t.start()
    side = None
    if during:
        time.sleep(max(0.0, min(warmup, seconds)))
        side = threading.Thread(target=during, daemon=True)
        side.start()
    join_until = deadline + 3  # a piece still in flight at the deadline isn't counted; don't wait long
    for t in threads:
        t.join(max(0.0, join_until - time.perf_counter()))
    if side:
        side.join(max(0.0, join_until + 10 - time.perf_counter()))
    return {"mbps": upload_rate(per_stream), "bytes": sent.value, "errors": errors[:3]}


def rate_from_samples(samples, window_start):
    """Megabits per second from (time, total bytes) samples, ignoring the warm-up period."""
    if len(samples) < 2:
        return None
    end = samples[-1]
    start = next((s for s in samples if s[0] >= window_start), None)
    if start is None or end[0] - start[0] < 1.0:
        start = samples[0]
    dt, db = end[0] - start[0], end[1] - start[1]
    if dt <= 0 or db <= 0:
        return None
    return round(db * 8 / dt / 1e6, 1)


def measure_throughput(worker, base, seconds, streams, warmup, during=None):
    counter, errors = _Counter(), []
    t0 = time.perf_counter()
    deadline = t0 + seconds
    threads = [threading.Thread(target=worker, args=(base, deadline, counter, errors), daemon=True)
               for _ in range(streams)]
    for t in threads:
        t.start()
    side = None
    samples = [(t0, 0)]
    while True:
        now = time.perf_counter()
        if now >= deadline:
            break
        if during and side is None and now - t0 >= warmup:
            side = threading.Thread(target=during, daemon=True)
            side.start()
        time.sleep(min(0.2, max(0.0, deadline - now)))
        samples.append((time.perf_counter(), counter.value))
    join_until = deadline + 5
    for t in threads:
        t.join(max(0.0, join_until - time.perf_counter()))
    if side:
        side.join(max(0.0, join_until + 10 - time.perf_counter()))
    return {"mbps": rate_from_samples(samples, t0 + warmup), "bytes": counter.value,
            "errors": errors[:3]}


def speed_preflight(base):
    try:
        with _http(base + "/__down?bytes=0", timeout=10) as resp:
            resp.read()
    except Exception as exc:
        hint = None
        if isinstance(getattr(exc, "reason", exc), ssl.SSLCertVerificationError) or \
                "CERTIFICATE_VERIFY_FAILED" in str(exc):
            hint = ("Python could not check the test server's security certificate. On a Mac, open "
                    "the Applications > Python 3.x folder and double-click 'Install Certificates.command', "
                    "then run this again.")
        return False, None, "%s: %s" % (type(exc).__name__, exc), hint
    colo = None
    try:
        with _http(base + "/cdn-cgi/trace", timeout=6) as resp:
            m = re.search(r"^colo=(\w+)", resp.read(4096).decode("ascii", "replace"), re.M)
            colo = m.group(1) if m else None
    except Exception:
        pass
    return True, colo, None, None


def run_speed_test(base, seconds):
    ok, colo, err, hint = speed_preflight(base)
    if not ok:
        return {"error": err, "hint": hint}
    warmup = min(2.0, seconds / 4.0)
    # About one ping per second while the line is busy. Same target (1.1.1.1) as the idle
    # measurement, and a long timeout, because bad lag can mean replies taking seconds.
    loaded_ping_count = max(3, int(seconds - warmup - 1.5))
    loaded_down, loaded_up = {}, {}

    def pinger(store):
        return lambda: store.update(ping_stats("1.1.1.1", loaded_ping_count, 3000) or {})

    down = measure_throughput(download_worker, base, seconds, 4, warmup, during=pinger(loaded_down))
    up = measure_upload(base, seconds, 3, warmup, during=pinger(loaded_up))
    measured = [x for x in (loaded_down, loaded_up) if x.get("sent")]
    worst = max(measured, key=lambda x: (x.get("loss_pct") or 0, x.get("median_ms") or 0)) if measured else None
    return {"server": colo, "download_mbps": down["mbps"], "upload_mbps": up["mbps"],
            "download_mb": round(down["bytes"] / 1e6), "upload_mb": round(up["bytes"] / 1e6),
            "loaded_latency": worst,
            "loaded_latency_download": loaded_down or None, "loaded_latency_upload": loaded_up or None,
            "download_errors": down["errors"], "upload_errors": up["errors"],
            "errors": down["errors"] + up["errors"]}


# --------------------------------------------------------------------------
# Turning measurements into advice
# --------------------------------------------------------------------------

LEVEL_ORDER = {"ACTION": 0, "CHECK": 1, "TIP": 2, "GOOD": 3}

PLACEMENT_ADVICE = (
    "Put the router in a central, open, raised spot (not in a cupboard, behind the TV or on "
    "the floor), away from microwaves, cordless phones, baby monitors, mirrors, fish tanks "
    "and thick or metal walls. If some rooms are always weak, a mesh Wi-Fi system (or a "
    "second access point wired to the router) works better than a plug-in range extender.")


def build_findings(d, plan_down=None, plan_up=None):
    findings = []

    def add(level, area, title, detail=""):
        findings.append({"level": level, "area": area, "title": title, "detail": detail})

    basics = d.get("network") or {}
    for note in basics.get("notes", []):
        add("CHECK", "Network", note)

    wifi = d.get("wifi") or {}
    lat = d.get("latency") or {}
    speed = d.get("speed") or {}
    on_wifi = bool(wifi.get("connected"))
    # Did the measurements actually go over Wi-Fi? Not for a laptop that is also on a cable.
    wifi_path = on_wifi and wifi.get("carries_traffic") is not False
    wifi_unknown = not on_wifi and bool(wifi.get("note"))  # e.g. Windows hid the Wi-Fi details
    link_rate = max([r for r in (wifi.get("rx_rate"), wifi.get("tx_rate")) if r] or [0]) or None
    dl, ul = speed.get("download_mbps"), speed.get("upload_mbps")
    # Some adapters report a very low link rate while idle; a fast download proves it wrong.
    link_rate_disproved = bool(link_rate and dl and wifi_path and dl > 0.7 * link_rate)

    # ---- Wi-Fi connection -------------------------------------------------
    if wifi.get("note"):
        add("CHECK" if not on_wifi else "TIP", "Wi-Fi", "Some Wi-Fi details were hidden by the system",
            wifi["note"])
    if on_wifi and wifi.get("carries_traffic") is False:
        add("TIP", "Network", "This computer is also connected by cable",
            "Its internet traffic goes through '%s' rather than Wi-Fi, so the speed and response-time "
            "results describe the cable connection. The Wi-Fi details are still accurate. To test the "
            "Wi-Fi itself, unplug the cable and run the check again." % basics.get("interface"))
    if on_wifi:
        rssi = wifi.get("rssi")
        est = " - estimated from %s%% signal" % wifi.get("signal_pct") if wifi.get("rssi_estimated") else ""
        if rssi is not None:
            label = signal_label(rssi)
            if label in ("Strong", "Good"):
                add("GOOD", "Wi-Fi", "Wi-Fi signal is %s (%d dBm%s)" % (label.lower(), rssi, est))
            elif label == "Fair":
                add("CHECK", "Wi-Fi", "Wi-Fi signal is only fair (%d dBm%s)" % (rssi, est),
                    "At this strength speed drops and video calls can stutter. Test again "
                    "standing near the router: if it's much better there, distance or walls are "
                    "the problem. " + PLACEMENT_ADVICE)
            else:
                add("ACTION", "Wi-Fi", "Wi-Fi signal is weak (%d dBm%s)" % (rssi, est),
                    "A weak signal is the most common cause of slow Wi-Fi. Move closer to the "
                    "router or move the router. " + PLACEMENT_ADVICE)
        if wifi.get("noise") is not None and rssi is not None:
            snr = rssi - wifi["noise"]
            # a low ratio with a normal noise floor just means a weak signal (reported above)
            if snr < 20 and (wifi["noise"] > -85 or rssi >= -67):
                add("CHECK", "Wi-Fi", "Lots of radio interference (signal is only %d dB above the noise)" % snr,
                    "Something nearby is drowning out the Wi-Fi: other networks on the same channel, "
                    "a microwave, cordless phone, Bluetooth gear or a poorly shielded USB 3 device. "
                    "Try another channel or the 5 GHz band.")

        band, ch = wifi.get("band"), wifi.get("channel")
        chan = d.get("channels") or {}
        if band == "2.4 GHz":
            if rssi is not None and rssi >= -67:
                where = ""
                if chan.get("own_on_other_bands"):
                    where = "Your network is also broadcasting on %s. " % " and ".join(chan["own_on_other_bands"])
                add("TIP", "Wi-Fi", "You're on the slower 2.4 GHz band even though the signal is good",
                    where + "The 5 GHz band is usually several times faster at close-to-medium range "
                    "and less crowded. If your router shows a separate network (often ending in "
                    "'5G'), connect this device to it - or turn on 'Smart Connect' / 'band steering' "
                    "so devices choose automatically. Keep 2.4 GHz for far-away rooms and smart gadgets.")
            if ch and ch not in (1, 6, 11):
                add("CHECK", "Wi-Fi", "Your 2.4 GHz channel (%d) overlaps its neighbours" % ch,
                    "Only channels 1, 6 and 11 don't overlap each other. In the router's wireless "
                    "settings pick 1, 6 or 11 (see the crowding numbers in section 2).")
            best = chan.get("best_24")
            if best and ch and best != ch and chan.get("own_score", 0) - chan["scores_24"].get(best, 0) >= 2:
                add("TIP", "Wi-Fi", "Channel %d looks less crowded than your channel %d" % (best, ch),
                    "Nearby networks crowd your current channel. Setting the router's 2.4 GHz "
                    "channel to %d may give a steadier connection. ('Auto' doesn't always pick well.)" % best)
        elif band in ("5 GHz", "6 GHz"):
            if chan.get("same_channel_strong", 0) >= 3:
                add("TIP", "Wi-Fi", "%d strong nearby networks share your %s channel %s" %
                    (chan["same_channel_strong"], band, ch),
                    "Picking a different 5 GHz channel in the router (for example 36, 44, 149 or "
                    "157) may help. Avoid very wide 160 MHz channels in crowded apartment blocks.")
            if band in ("5 GHz", "6 GHz") and rssi is not None and rssi >= -67:
                add("GOOD", "Wi-Fi", "Connected on the fast %s band" % band)

        level, label = wifi.get("security_level"), wifi.get("security_label")
        if level == "critical":
            add("ACTION", "Security", "Your Wi-Fi is not properly protected: %s" % label,
                "Anyone nearby could join your network or watch your traffic. In the router's "
                "Wi-Fi (wireless security) settings choose WPA2-Personal (AES) or WPA3-Personal, "
                "set a new long password (at least 12 characters - a few random words works well), "
                "save, and reconnect your own devices with the new password.")
        elif level == "weak":
            add("ACTION", "Security", "Your Wi-Fi uses outdated security: %s" % label,
                "Switch the router to WPA2-Personal with AES (also called CCMP), or WPA3. "
                "This is both safer and faster: old TKIP encryption limits Wi-Fi speed.")
        elif level == "fair":
            add("CHECK", "Security", "Your Wi-Fi has no password: %s" % label,
                "Unless this is a deliberate public network, set WPA2/WPA3 with a password.")
        elif level == "good":
            add("GOOD", "Security", "Wi-Fi is encrypted with %s" % label)
            add("TIP", "Security", "Consider WPA3 if your router offers it",
                "Look for 'WPA3-Personal' or 'WPA2/WPA3' in the router's Wi-Fi security settings. "
                "If an old device stops connecting afterwards, switch back to WPA2 (AES).")
        elif level == "strong":
            add("GOOD", "Security", "Wi-Fi is encrypted with %s" % label)

        if link_rate and not link_rate_disproved:
            if link_rate < 30:
                add("CHECK", "Wi-Fi", "Your Wi-Fi link was running at only %g Mbps" % link_rate,
                    "This is the raw speed between this device and the router; real downloads get "
                    "about half of it. Weak signal, the 2.4 GHz band, interference or an old Wi-Fi "
                    "adapter cause this - see the signal and band advice. (Some devices show a low "
                    "figure while idle; if the speed test result is fine, ignore this.)")
            elif plan_down and wifi_path and link_rate < plan_down * 1.6:
                add("CHECK", "Wi-Fi", "Your Wi-Fi link (%g Mbps) can't carry your full %g Mbps plan" %
                    (link_rate, plan_down),
                    "Wi-Fi usually delivers 50-70% of its link speed. To get your full plan on this "
                    "device, improve the signal, use 5 GHz, or use an Ethernet cable.")
        gen = wifi.get("generation")
        if gen in ("Wi-Fi 4", "older than Wi-Fi 4") and (not plan_down or plan_down >= 50):
            add("TIP", "Wi-Fi", "This connection uses %s (%s)" % (gen, wifi.get("standard")),
                "Either this device or the router is several generations old. With a fast plan, a "
                "Wi-Fi 5 or Wi-Fi 6 router - or a newer Wi-Fi adapter for this device - can roughly "
                "double or triple real speeds.")
    elif not wifi.get("note"):
        add("TIP", "Wi-Fi", "This computer isn't using Wi-Fi right now",
            "If it's connected by cable, the speed results show what your internet line can do "
            "without Wi-Fi in the way - a useful baseline. Run the check again on a Wi-Fi laptop "
            "in the rooms where it feels slow and compare.")

    # ---- Response times -------------------------------------------------
    router = lat.get("router") or {}
    internet = lat.get("internet") or {}
    router_ping_reliable = True
    if router.get("received") and internet.get("received") and \
            router["median_ms"] > internet["median_ms"] + 5:
        router_ping_reliable = False  # router answers its own pings slowly; that's harmless
    if router.get("sent"):
        if not router.get("received"):
            add("TIP", "Router", "Your router doesn't answer pings",
                "Many routers ignore pings - that is normal and not a problem by itself.")
        elif router_ping_reliable:
            loss, med, jit = router["loss_pct"], router["median_ms"], router["jitter_ms"]
            link = "Wi-Fi link" if wifi_path else "connection"
            area = "Wi-Fi" if wifi_path else "Router"
            if loss >= 5:
                add("ACTION", area, "%g%% of packets were lost between this computer and the router" % loss,
                    "Losses this close to home point to a Wi-Fi problem (weak signal or "
                    "interference) or an overloaded router. Try near the router; restart the "
                    "router; see the signal and channel advice." if wifi_path else
                    "Losses this close to home point to a faulty cable or network port, or an "
                    "overloaded router. Restart the router and try another cable or port.")
            elif loss > 0:
                add("CHECK", area, "A few packets (%g%%) were lost on the way to the router" % loss,
                    "Occasional loss on the way to the router causes brief stalls in calls and games.")
            if med > 30 or jit > 20:
                add("CHECK", area, "Your %s to the router is slow or unsteady "
                    "(typical %g ms, jitter %g ms)" % (link, med, jit),
                    "A healthy home connection usually answers in under 10 ms. Busy channels, weak "
                    "signal or heavy use by other devices cause this.")
            elif med <= 10 and loss == 0:
                add("GOOD", area, "Your %s to the router is quick and steady (%g ms)" % (link, med))
    if internet.get("received"):
        loss, med, jit = internet["loss_pct"], internet["median_ms"], internet["jitter_ms"]
        router_measured = bool(router.get("received")) and router_ping_reliable
        if loss >= 2:
            if router_measured and router["loss_pct"] < 1:
                add("CHECK", "Provider", "%g%% of packets were lost beyond your router" % loss,
                    "The loss happens after your router, so it's the modem, the line or your "
                    "provider. Restart the modem/router. If it keeps happening at different times "
                    "of day, report 'packet loss' to your internet provider.")
            elif not (router_measured and router["loss_pct"] >= 2):  # not already explained above
                add("CHECK", "Provider", "%g%% of packets to the internet were lost" % loss,
                    "Your router doesn't answer pings reliably, so it can't be told whether the loss "
                    "is on your Wi-Fi or beyond the router. Restart the modem and router. If it "
                    "continues on a computer plugged in by cable, it's the line or your provider.")
        if med > 100:
            add("CHECK", "Provider", "Internet response time is high (%g ms)" % med,
                "Under 50 ms is typical for cable or fibre. Satellite and some mobile links are "
                "naturally higher. If you're on cable/fibre, restart your modem and router and "
                "check again later.")
        elif med <= 50 and loss == 0:
            add("GOOD", "Provider", "Internet response time is good (%g ms)" % med)
        if jit > 30:
            add("CHECK", "Provider", "Internet response time jumps around (jitter %g ms)" % jit,
                "Big swings make video calls and games stutter. Check whether other devices are "
                "streaming or downloading at the same time.")
    elif lat:
        add("ACTION", "Provider", "No replies from the internet",
            "Pings to Cloudflare and Google got no answers. If web pages also don't load, restart "
            "the modem and router and check your provider for an outage.")

    # ---- Bufferbloat -------------------------------------------------------
    loaded = speed.get("loaded_latency") or {}
    cloudflare_idle = lat.get("Cloudflare") or {}
    idle = cloudflare_idle if cloudflare_idle.get("received") else internet  # same target as under load
    if loaded.get("sent") and idle.get("received"):
        rise = loaded["median_ms"] - idle["median_ms"] if loaded.get("received") else None
        lost = loaded.get("loss_pct") or 0
        what = ", ".join(x for x in ("+%d ms" % rise if rise is not None else None,
                                     "%g%% of replies lost" % lost if lost >= 20 else None) if x)
        if lost >= 50 or (rise is not None and rise >= 100):
            add("ACTION", "Router", "Everything lags while the connection is busy (%s)" % what,
                "This is called bufferbloat: when one device downloads, streams or backs up, calls "
                "and games stall for everyone. In the router look for 'QoS', 'Smart Queue "
                "Management (SQM)', 'Adaptive QoS' or 'bandwidth control', turn it on and enter "
                "about 90% of your plan's speeds. Not every router has this; if yours doesn't, it's "
                "a good reason to choose one that does next time.")
        elif lost >= 20 or (rise is not None and rise >= 30):
            add("TIP", "Router", "Response time rises while the line is busy (%s)" % what,
                "Mild bufferbloat. If calls stutter while others stream or download, turn on QoS / "
                "Smart Queue Management in the router.")
        else:
            add("GOOD", "Router", "Response time stays low even while the line is busy")

    # ---- Speed -------------------------------------------------------------
    if speed.get("error"):
        add("CHECK", "Speed", "The speed test couldn't run",
            (speed.get("hint") or "") + " (Details: %s) You can test in a web browser instead at "
            "speed.cloudflare.com or fast.com." % speed["error"])
    elif "download_mbps" in speed:
        for part, value, errs in (("download", dl, speed.get("download_errors")),
                                  ("upload", ul, speed.get("upload_errors"))):
            if not value:
                add("CHECK", "Speed", "The %s part of the speed test didn't finish" % part,
                    ("The error was: %s. " % errs[0] if errs else "") + "Try again later, or test in a "
                    "web browser at speed.cloudflare.com or fast.com.")
    if dl:
        def why_slow():
            if wifi_unknown:
                return ("Wi-Fi details were hidden (see above), so it isn't clear whether Wi-Fi or the "
                        "line is the limit. Allow the details and run again, or test on a computer "
                        "plugged into the router with a cable.")
            if not wifi_path:
                return ("This test didn't go over Wi-Fi, so this is roughly your line speed. Restart "
                        "the modem and router; if it stays low, contact your provider with these numbers.")
            if link_rate and dl >= 0.45 * link_rate:
                return ("Your Wi-Fi link (%g Mbps) is the bottleneck: Wi-Fi delivers about half its "
                        "link speed. A stronger signal or the 5 GHz band will raise it." % link_rate)
            if (wifi.get("rssi") or 0) < -67 or router.get("loss_pct", 0) >= 2:
                return "Your Wi-Fi quality looks poor (see the Wi-Fi items), which holds the speed down."
            return ("Your Wi-Fi link looks healthy, so the slowdown is more likely the router, modem "
                    "or provider. Try, in order: (1) pause big downloads, streams and cloud backups on "
                    "other devices, (2) restart the modem and router, (3) test on a computer plugged "
                    "into the router with a cable. If it's still slow by cable, contact your provider.")
        if plan_down:
            ratio = dl / plan_down
            if ratio >= 0.8:
                add("GOOD", "Speed", "Download %g Mbps - %d%% of your %g Mbps plan" % (dl, ratio * 100, plan_down))
            else:
                add("ACTION" if ratio < 0.5 else "CHECK", "Speed",
                    "Download %g Mbps is only %d%% of your %g Mbps plan" % (dl, ratio * 100, plan_down),
                    why_slow())
        else:
            if dl < 10:
                add("CHECK", "Speed", "Download speed is slow (%g Mbps)" % dl, why_slow())
            elif dl < 25:
                add("TIP", "Speed", "Download speed is basic (%g Mbps)" % dl,
                    "Enough for one HD stream; several people at once will feel it. " + why_slow())
            else:
                add("GOOD", "Speed", "Download speed is %g Mbps" % dl)
            add("TIP", "Speed", "Compare with what you pay for",
                "Run again with your plan speed, e.g. 'python3 wifi_checkup.py --plan 100', to see "
                "whether you're getting what you pay for.")
        if dl > 400:
            add("TIP", "Speed", "At speeds this high the test itself may be the limit",
                "For gigabit-class plans, also try speed.cloudflare.com in a browser.")
    if ul:
        if plan_up:
            ratio = ul / plan_up
            if ratio >= 0.8:
                add("GOOD", "Speed", "Upload %g Mbps - %d%% of your %g Mbps plan" % (ul, ratio * 100, plan_up))
            else:
                add("CHECK", "Speed", "Upload %g Mbps is only %d%% of your %g Mbps plan" % (ul, ratio * 100, plan_up),
                    "Upload matters for video calls and cloud backups. The same causes as slow "
                    "download apply.")
        elif ul < 3:
            add("CHECK", "Speed", "Upload speed is low (%g Mbps)" % ul,
                "Video calls need 2-4 Mbps upload each. Check that nothing (cloud backup, camera "
                "uploads) is uploading in the background.")

    # ---- DNS ----------------------------------------------------------------
    dns = d.get("dns") or []
    current = [s for s in dns if s["role"] == "current"]
    publics = [s for s in dns if s["role"] == "public" and s.get("median_ms") is not None]
    best = min(publics, key=lambda s: s["median_ms"]) if publics else None
    cur = next((s for s in current if s.get("median_ms") is not None), None)
    if current and not cur and best:
        add("CHECK", "DNS", "Your DNS server didn't answer the test lookups",
            "DNS turns names like google.com into addresses. If websites are slow to start "
            "loading, set the router's DNS to %s (%s) or another public DNS." % (best["ip"], best["label"]))
    elif cur and best:
        if cur["median_ms"] - best["median_ms"] > 25 and cur["median_ms"] > 1.5 * best["median_ms"]:
            add("TIP", "DNS", "A faster DNS service is available (%s: %g ms vs yours: %g ms)" %
                (best["label"], best["median_ms"], cur["median_ms"]),
                "Every new website starts with a DNS lookup, so a faster one makes pages start "
                "loading sooner. Change the DNS setting in the router (often under Internet/WAN or "
                "DHCP settings) to %s so every device benefits. Popular choices: 1.1.1.1 "
                "(Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9)." % best["ip"])
        elif cur["median_ms"] <= 60:
            add("GOOD", "DNS", "DNS lookups are quick (%g ms)" % cur["median_ms"])

    # ---- Devices --------------------------------------------------------------
    scan = d.get("scan") or {}
    devices = scan.get("devices") or []
    if scan.get("skipped"):
        add("CHECK", "Devices", "The device scan was skipped", scan["skipped"])
    elif devices:
        new = [x for x in devices if x.get("status") == "NEW"]
        if d.get("first_device_scan"):
            add("TIP", "Devices", "%d devices found - saved as your starting list" % len(devices),
                "Go through the list in section 5. Name the ones you recognise (see 'Naming your "
                "devices' at the end) so future checks flag any newcomer. Anything you can't place "
                "is worth a closer look in the router's own client list.")
        if new:
            listing = "; ".join("%s (%s, %s)" % (display_name(x), x["ip"], x.get("mac")) for x in new)
            add("CHECK", "Devices", ("1 device on your network wasn't there last time" if len(new) == 1 else
                                     "%d devices on your network weren't there last time" % len(new)),
                listing + ". If you don't recognise one: (1) look it up in the router's "
                "connected-devices list, (2) switch your own devices off one at a time and scan again, "
                "(3) if it's still a mystery, change the Wi-Fi password (with WPA2/WPA3) - that "
                "disconnects everyone - then reconnect only your own devices. Note: phones often use "
                "a 'private' address that changes, so a family phone can look new.")
        elif not d.get("first_device_scan"):
            add("GOOD", "Devices", "No new devices since the last check (%d online now)" % len(devices))
        if any(x.get("random_mac") for x in devices if not x.get("is_this_computer")):
            add("TIP", "Devices", "Some devices use 'private' (randomised) addresses",
                "These are marked 'private' in the list. They're usually phones, tablets or laptops "
                "with the privacy feature turned on - not a sign of an intruder. The phone's Wi-Fi "
                "settings show its private address, so you can match it.")

    # ---- Router -----------------------------------------------------------------
    rt = d.get("router") or {}
    ports = {p["port"] for p in rt.get("open_ports", [])}
    if 23 in ports:
        add("CHECK", "Security", "Your router accepts Telnet connections",
            "Telnet is an old, unencrypted way to manage devices. Turn it off in the router "
            "(often under Administration or Management) and update the router's firmware.")
    if ports & {21, 445}:
        add("TIP", "Security", "File sharing is switched on in your router",
            "Usually for a USB drive plugged into the router. If you don't use it, turn it off; "
            "if you do, make sure it needs a password.")
    if rt.get("upnp"):
        add("TIP", "Security", "UPnP is switched on in your router",
            "UPnP lets devices open doors through your router by themselves. Game consoles and "
            "some apps need it; if you have none, turning it off makes the network a bit safer. "
            "If you keep it on, keep the router's firmware updated.")
    return sorted(findings, key=lambda f: LEVEL_ORDER[f["level"]])


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

MARK = {"ACTION": "[!!]", "CHECK": "[? ]", "TIP": "[i ]", "GOOD": "[ok]"}


def wrap(text, indent=7, width=78):
    return textwrap.fill(text, width=width, initial_indent=" " * indent, subsequent_indent=" " * indent)


def fmt_ms(stats):
    if not stats or not stats.get("received"):
        return "no replies" if stats and stats.get("sent") else "not measured"
    s = "typical %g ms, jitter %g ms, lost %g%%" % (stats["median_ms"], stats["jitter_ms"], stats["loss_pct"])
    if stats.get("method") == "tcp":
        s += " (measured with TCP)"
    return s


def render_report(d, findings):
    out = []
    w = out.append
    wifi = d.get("wifi") or {}
    basics = d.get("network") or {}
    w("=" * 78)
    w(" WI-FI CHECKUP REPORT    %s    %s" % (d["started"].replace("T", " "), d["os"]))
    w("=" * 78)
    w("")
    w("SUMMARY - most important first")
    w("  [!!] act on this   [? ] worth checking   [i ] tip   [ok] looks fine")
    w("")
    for f in findings:
        w("  %s %s" % (MARK[f["level"]], f["title"]))
        if f["detail"] and f["level"] != "GOOD":
            w(wrap(f["detail"]))
    w("")

    w("1. YOUR WI-FI CONNECTION")
    if wifi.get("connected"):
        rows = [("Network name", wifi.get("ssid") or "(hidden by your system)")]
        if wifi.get("band") or wifi.get("channel"):
            s = ", ".join(x for x in (wifi.get("band"), "channel %s" % wifi["channel"] if wifi.get("channel") else None) if x)
            if wifi.get("width_mhz"):
                s += " (%d MHz wide)" % wifi["width_mhz"]
            rows.append(("Band / channel", s))
        if wifi.get("rssi") is not None:
            s = "%d dBm - %s" % (wifi["rssi"], signal_label(wifi["rssi"]))
            if wifi.get("rssi_estimated"):
                s += " (estimated from %s%%)" % wifi.get("signal_pct")
            if wifi.get("noise") is not None:
                s += ", noise %d dBm" % wifi["noise"]
            rows.append(("Signal", s))
        rates = [("receive", wifi.get("rx_rate")), ("send", wifi.get("tx_rate"))]
        rates = ["%g Mbps %s" % (r, n) for n, r in rates if r]
        if rates:
            rows.append(("Link speed", " / ".join(rates)))
        if wifi.get("standard"):
            rows.append(("Wi-Fi standard", wifi["standard"] + (" (%s)" % wifi["generation"] if wifi.get("generation") else "")))
        if wifi.get("security"):
            rows.append(("Security", wifi["security"] + (" / " + wifi["cipher"] if wifi.get("cipher") else "")))
        if wifi.get("interface"):
            rows.append(("Adapter", wifi["interface"]))
        for k, v in rows:
            w("   %-16s %s" % (k, v))
        w("   (Signal guide: -30 to -60 dBm strong, -60 to -67 good, -67 to -75 fair, below -75 weak)")
    else:
        w("   Not connected by Wi-Fi" + (" - " + wifi["note"] if wifi.get("note") else "."))
    w("")

    chan = d.get("channels") or {}
    nearby = d.get("nearby") or []
    w("2. NEARBY WI-FI NETWORKS (%d seen)" % len(nearby))
    if nearby:
        c24 = chan.get("counts_24") or {}
        if any(c24.values()):
            w("   2.4 GHz networks overlapping each main channel: " +
              ", ".join("ch %d: %d" % (c, c24.get(c, 0)) for c in (1, 6, 11)) +
              ("  -> quietest: %d" % chan["best_24"] if chan.get("best_24") else ""))
        if "same_channel" in chan:
            w("   Other networks on your channel: %d (%d of them strong)" %
              (chan["same_channel"], chan.get("same_channel_strong", 0)))
        if "overlapping" in chan:
            w("   Other 2.4 GHz networks overlapping your channel: %d" % chan["overlapping"])
        strongest = sorted([n for n in nearby if n.get("rssi") is not None], key=lambda n: -n["rssi"])[:8]
        if strongest:
            w("   Strongest nearby:")
            for n in strongest:
                w("     %-28s %-8s ch %-4s %4d dBm  %s" % (clean_text(n.get("ssid") or "(hidden)", 28),
                  n.get("band") or "", n.get("channel") or "?", n["rssi"], n.get("security") or ""))
    else:
        w("   Not available on this system.")
    w("")

    lat = d.get("latency") or {}
    w("3. RESPONSE TIMES (lower and steadier is better)")
    if lat.get("router") is not None:
        w("   %-27s %s" % ("Router (%s)" % lat["router"].get("host"), fmt_ms(lat["router"])))
    for _ip, label in PUBLIC_PING_TARGETS:
        if lat.get(label) is not None:
            w("   %-27s %s" % ("Internet - %s" % label, fmt_ms(lat[label])))
    dns = d.get("dns") or []
    if dns:
        w("   DNS lookups (typical time per lookup):")
        for s in dns:
            v = "%g ms" % s["median_ms"] if s.get("median_ms") is not None else "no answer"
            w("     %-31s %-16s %s" % (s["label"], s["ip"], v))
    w("")

    sp = d.get("speed")
    w("4. INTERNET SPEED" + (" (test server: %s)" % sp["server"] if sp and sp.get("server") else ""))
    if not sp:
        w("   Skipped.")
    elif sp.get("error"):
        w("   Could not run: %s" % sp["error"])
        if sp.get("hint"):
            w(wrap(sp["hint"], 3))
    else:
        for label, key in (("Download", "download"), ("Upload", "upload")):
            value = sp.get(key + "_mbps")
            errs = sp.get(key + "_errors") or []
            w("   %-15s %s" % (label, "%g Mbps" % value if value else
                               "did not finish" + (" (%s)" % clean_text(errs[0], 50) if errs else "")))
        idle = ((lat.get("Cloudflare") or {}) if (lat.get("Cloudflare") or {}).get("received")
                else (lat.get("internet") or {})).get("median_ms")
        for label, key in (("During download", "loaded_latency_download"), ("During upload", "loaded_latency_upload")):
            st = sp.get(key)
            if st and st.get("sent"):
                text = ("typical %g ms response time" % st["median_ms"]) if st.get("received") else \
                    "replies timed out"
                if st.get("received") and st.get("loss_pct"):
                    text += ", %g%% lost" % st["loss_pct"]
                if idle is not None:
                    text += " (idle: %g ms)" % idle
                w("   %-15s %s" % (label, text))
        w("   Data used       about %d MB down, %d MB up" % (sp.get("download_mb", 0), sp.get("upload_mb", 0)))
    w("")

    scan = d.get("scan") or {}
    devices = scan.get("devices") or []
    w("5. DEVICES ON YOUR NETWORK RIGHT NOW (%d)" % len(devices))
    if scan.get("skipped"):
        w(wrap(scan["skipped"], 3))
    elif devices:
        w("   %-15s %-17s %-10s %s" % ("Address", "Hardware (MAC)", "Status", "Name / description"))
        for x in devices:
            mac = x.get("mac") or "-"
            status = x.get("status") or ""
            name = display_name(x)
            extras = []
            if x.get("is_router"):
                extras.append("your router")
            if x.get("random_mac"):
                extras.append("private address")
            model = (x.get("upnp") or {}).get("modelName")
            if x.get("is_router") and model and model not in name:
                extras.append(clean_text(model, 30))
            line = "   %-15s %-17s %-10s %s" % (x["ip"], mac, status, clean_text(name, 30))
            if extras:
                line += " [" + ", ".join(extras) + "]"
            w(line)
        w("")
        w(wrap("This list only shows devices that are switched on and awake right now. Your router's "
               "own 'connected devices' page is the complete record, including sleeping devices.", 3))
        if scan.get("note"):
            w(wrap(scan["note"], 3))
    w("")

    rt = d.get("router") or {}
    w("6. YOUR ROUTER")
    if rt.get("ip"):
        w("   Address         %s" % rt["ip"])
        w("   Admin page      %s  (open it in a web browser on this network)" %
          (rt.get("admin_url") or "http://%s" % rt["ip"]))
        web = rt.get("web") or {}
        if web.get("title"):
            w("   Page title      %s" % web["title"])
        if web.get("redirects_to"):
            w("   Redirects to    %s" % web["redirects_to"])
        if rt.get("model"):
            w("   Model           %s" % rt["model"])
        if rt.get("open_ports") is not None:
            w("   Services open   %s" % (", ".join("%s (%d)" % (p["service"], p["port"]) for p in rt["open_ports"]) or "none of the common ones"))
        w("   UPnP            %s" % ("on" if rt.get("upnp") else "not detected"))
    else:
        w("   Router not found.")
    w("")

    w("ROUTER CHECKLIST - things only the router's admin page can show")
    admin = rt.get("admin_url") or "your router's address"
    w(wrap("Log in at %s. The default login is usually printed on a sticker on the router. "
           "If your router came from your internet provider, the provider's app may show the "
           "same settings." % admin, 3))
    for item in [
        "Connected-devices list ('Attached devices', 'DHCP clients', 'Client list'): anything you "
        "don't recognise? Most routers can block a device from there.",
        "Admin password changed from the default on the sticker (this is different from the Wi-Fi password).",
        "Wi-Fi security set to WPA2-Personal (AES) or WPA3 - never WEP, WPA/TKIP or 'Open'.",
        "WPS turned off (the push-button / PIN pairing feature can be attacked).",
        "Remote management / 'access from the internet' turned off.",
        "Firmware up to date ('Firmware update' / 'Check for updates'; turn on automatic updates if offered).",
        "A guest network for visitors and smart gadgets, so they can't reach your computers.",
        "Restart the router now and then (for example once a month) - it clears slowdowns.",
    ]:
        w(textwrap.fill(item, width=78, initial_indent="   [ ] ", subsequent_indent="       "))
    w("")
    w("NAMING YOUR DEVICES")
    w(wrap("Give a device a name so future reports show it, for example:", 3))
    w("     python3 wifi_checkup.py --no-speed --name aa:bb:cc:dd:ee:ff \"Living room TV\"")
    w(wrap("Or edit %s directly." % d.get("known_devices_file", "known_devices.json"), 3))
    if INTERNAL_ERRORS:
        w("")
        w("CHECKER NOTES (some steps had problems; the rest of the report is still valid)")
        for e in INTERNAL_ERRORS[:10]:
            w("   - " + clean_text(e, 120))
    w("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Read-only checkup of your Wi-Fi, internet speed and the devices on your network. "
                    "It does not change any settings.")
    p.add_argument("--plan", type=float, metavar="MBPS", help="your internet plan's download speed in Mbps")
    p.add_argument("--plan-up", type=float, metavar="MBPS", help="your internet plan's upload speed in Mbps")
    p.add_argument("--no-speed", action="store_true", help="skip the speed test (it uses some data)")
    p.add_argument("--no-scan", action="store_true", help="skip the scan for devices on your network")
    p.add_argument("--quick", action="store_true", help="shorter measurements (less accurate)")
    p.add_argument("--vendors", action="store_true",
                   help="look up who made each device online (sends only the maker part of each address "
                        "to api.macvendors.com)")
    p.add_argument("--name", nargs=2, action="append", metavar=("MAC", "NAME"), default=[],
                   help="give a device a name, e.g. --name aa:bb:cc:dd:ee:ff \"Dad's phone\"")
    p.add_argument("--out", metavar="FOLDER", default=str(Path.home() / "wifi-checkup"),
                   help="where reports and the device list are saved (default: %(default)s)")
    p.add_argument("--speed-server", default=SPEED_BASE_URL, help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version="wifi_checkup " + VERSION)
    args = p.parse_args(argv)
    labels = {}
    for mac, name in args.name:
        m = norm_mac(mac)
        if not m:
            p.error("'%s' doesn't look like a hardware (MAC) address" % mac)
        labels[m] = name
    args.labels = labels
    return args


def step(msg):
    print("  ... " + msg, file=sys.stderr, flush=True)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = parse_args(argv)
    ping_count = 10 if args.quick else 20
    speed_seconds = 6 if args.quick else 10
    out_dir = Path(args.out).expanduser()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        out_dir = Path.cwd()

    started = datetime.datetime.now()
    d = {"tool_version": VERSION, "started": started.isoformat(timespec="seconds"),
         "os": "%s %s" % (platform.system(), platform.release()),
         "options": {"plan": args.plan, "plan_up": args.plan_up, "quick": args.quick}}
    print("\nWi-Fi checkup %s - read-only, changes no settings.\n" % VERSION, file=sys.stderr)

    step("Reading network settings")
    d["network"] = safe("network", get_network_basics) or {"notes": []}
    step("Reading Wi-Fi connection details")
    wifi_nearby = safe("wifi", get_wifi_info) or ({}, [])
    d["wifi"], d["nearby"] = wifi_nearby
    d["wifi"]["carries_traffic"] = wifi_carries_traffic(d["network"], d["wifi"])
    d["channels"] = safe("channels", analyze_channels, d["wifi"], d["nearby"]) or {}

    step("Measuring response times to your router and the internet (about %d seconds)" % ping_count)
    lat_dns = safe("latency", measure_latency_and_dns, d["network"], ping_count) or ({}, [])
    d["latency"], d["dns"] = lat_dns

    gateway = d["network"].get("gateway")
    if gateway:
        step("Checking the router")
        d["router"] = safe("router", check_router, gateway) or {"ip": gateway}

    known_path = out_dir / "known_devices.json"
    d["known_devices_file"] = str(known_path)
    if not args.no_scan:
        step("Looking for devices on your network (about 15 seconds)")
        d["scan"] = safe("scan", scan_devices, d["network"], d["wifi"]) or {"skipped": "The device scan failed."}
        devices = d["scan"].get("devices") or []
        if args.vendors and devices:
            step("Looking up device makers online")
            cache_file = out_dir / "vendor_cache.json"
            cache = load_json(cache_file) or {}
            safe("vendors", lookup_vendors, devices, cache)
            safe("vendor cache", save_json, cache_file, cache)
        if devices:
            router_dev = next((x for x in devices if x.get("is_router")), None)
            if router_dev:
                up = router_dev.get("upnp") or {}
                if d.get("router") is not None:
                    d["router"]["mac"] = router_dev.get("mac")
                    d["router"]["upnp"] = bool(up.get("is_gateway_device"))
                    model = " ".join(x for x in (up.get("manufacturer"), up.get("modelName"),
                                                 up.get("modelNumber")) if x)
                    d["router"]["model"] = model or up.get("friendlyName")
            key = (router_dev or {}).get("mac") or "%s/%s" % (gateway, d["wifi"].get("ssid"))
            res = safe("known devices", update_known_devices, known_path, key, devices, args.labels,
                       started.isoformat(timespec="seconds"))
            d["first_device_scan"] = bool(res and res[0])
    elif args.labels:
        print("Note: --name only takes effect during a device scan (drop --no-scan).", file=sys.stderr)

    if not args.no_speed:
        step("Running the speed test: download, then upload (about %d seconds). On a fast line this "
             "can use a few hundred MB of data." % (speed_seconds * 2 + 3))
        d["speed"] = safe("speed", run_speed_test, args.speed_server, speed_seconds) or \
            {"error": "speed test failed"}

    findings = build_findings(d, args.plan, args.plan_up)
    d["findings"] = findings
    d["internal_errors"] = INTERNAL_ERRORS
    report = render_report(d, findings)
    print("\n" + report)

    stamp = started.strftime("%Y%m%d-%H%M%S")
    txt_path, json_path = out_dir / ("wifi-report-%s.txt" % stamp), out_dir / ("wifi-report-%s.json" % stamp)
    try:
        txt_path.write_text(report, encoding="utf-8")
        save_json(json_path, d)
        print("Saved this report to:\n  %s\n  %s (details)" % (txt_path, json_path))
    except OSError as exc:
        print("Could not save the report: %s" % exc)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        sys.exit(130)
