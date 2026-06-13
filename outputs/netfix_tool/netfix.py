#!/usr/bin/env python3
"""
NetFix Inspector

Cross-platform network diagnostics and conservative repair helper.
The packet-level checks use Scapy when it is available and the process has
enough privileges. All destructive or system-changing actions require --apply.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as _dt
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict
from typing import Any, Iterable

VERSION = "1.0.0"
TOOL_NAME = "NetFix Inspector"

DEFAULT_V4_TARGETS = [
    ("1.1.1.1", 443, "Cloudflare HTTPS"),
    ("8.8.8.8", 53, "Google DNS TCP"),
    ("223.5.5.5", 443, "AliDNS HTTPS"),
]

DEFAULT_V6_TARGETS = [
    ("2606:4700:4700::1111", 443, "Cloudflare IPv6 HTTPS"),
    ("2001:4860:4860::8888", 53, "Google IPv6 DNS TCP"),
    ("2400:3200::1", 443, "AliDNS IPv6 HTTPS"),
]

DEFAULT_DNS_TEST_NAMES = ["example.com", "cloudflare.com"]

DNS_PROVIDERS = {
    "cloudflare": {
        "ipv4": ["1.1.1.1", "1.0.0.1"],
        "ipv6": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
    },
    "google": {
        "ipv4": ["8.8.8.8", "8.8.4.4"],
        "ipv6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    },
    "alidns": {
        "ipv4": ["223.5.5.5", "223.6.6.6"],
        "ipv6": ["2400:3200::1", "2400:3200:baba::1"],
    },
    "tencent": {
        "ipv4": ["119.29.29.29", "182.254.116.116"],
        "ipv6": [],
    },
    "quad9": {
        "ipv4": ["9.9.9.9", "149.112.112.112"],
        "ipv6": ["2620:fe::fe", "2620:fe::9"],
    },
}

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def local_now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def monotonic_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def normalize_ip_literal(value: str) -> str:
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    return value.split("%", 1)[0]


def safe_ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(normalize_ip_literal(value))
    except ValueError:
        return None


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def run_cmd(command: list[str], timeout: int = 15) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "").strip(),
            "stderr": (completed.stderr or "").strip(),
            "duration_ms": monotonic_ms(started),
        }
    except FileNotFoundError as exc:
        return {
            "command": command,
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_ms": monotonic_ms(started),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": 124,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": "command timed out",
            "duration_ms": monotonic_ms(started),
        }


def make_report(command: str) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "command": command,
        "started_at": local_now(),
        "started_at_utc": utc_now(),
        "host": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "admin": is_admin(),
        },
        "checks": [],
    }


def add_check(
    report: dict[str, Any],
    name: str,
    status: str,
    summary: str,
    details: dict[str, Any] | None = None,
    recommendations: list[str] | None = None,
) -> dict[str, Any]:
    item = {
        "name": name,
        "status": status.upper(),
        "summary": summary,
        "details": details or {},
        "recommendations": recommendations or [],
    }
    report["checks"].append(item)
    return item


def worst_status(statuses: Iterable[str]) -> str:
    order = {"FAIL": 4, "WARN": 3, "SKIP": 2, "INFO": 1, "OK": 0}
    worst = "OK"
    for status in statuses:
        if order.get(status.upper(), 0) > order.get(worst, 0):
            worst = status.upper()
    return worst


def finish_report(report: dict[str, Any]) -> dict[str, Any]:
    report["finished_at"] = local_now()
    report["finished_at_utc"] = utc_now()
    counts = Counter(check["status"] for check in report["checks"])
    report["summary"] = {
        "status": worst_status(counts.keys()) if counts else "INFO",
        "counts": dict(counts),
    }
    return report


def print_text_report(report: dict[str, Any]) -> None:
    print(f"{report['tool']} {report['version']}")
    print(f"Host: {report['host']['hostname']}  System: {report['host']['platform']}")
    print(f"Started: {report['started_at']}  Admin/root: {report['host']['admin']}")
    print("")
    for check in report["checks"]:
        print(f"[{check['status']}] {check['name']}: {check['summary']}")
        details = check.get("details") or {}
        highlights = details.get("highlights") or []
        for line in highlights[:8]:
            print(f"  - {line}")
        for rec in (check.get("recommendations") or [])[:6]:
            print(f"  * 建议: {rec}")
        if highlights or check.get("recommendations"):
            print("")
    summary = report.get("summary") or {}
    if summary:
        counts = ", ".join(f"{key}={value}" for key, value in sorted(summary["counts"].items()))
        print(f"Overall: {summary['status']} ({counts})")


def save_report_if_needed(report: dict[str, Any], output_path: str | None) -> None:
    if not output_path:
        return
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)


def emit_report(report: dict[str, Any], args: argparse.Namespace) -> int:
    finish_report(report)
    save_report_if_needed(report, getattr(args, "output", None))
    if getattr(args, "json", False):
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_text_report(report)
        if getattr(args, "output", None):
            print(f"\nJSON report saved: {os.path.abspath(args.output)}")
    if getattr(args, "strict_exit", False):
        return 1 if report["summary"]["status"] in {"FAIL", "WARN"} else 0
    return 0


def load_psutil():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:
        return None


def collect_interfaces() -> list[dict[str, Any]]:
    psutil = load_psutil()
    interfaces: list[dict[str, Any]] = []
    if not psutil:
        return interfaces

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, addr_list in addrs.items():
        stat = stats.get(name)
        item: dict[str, Any] = {
            "name": name,
            "is_up": bool(stat.isup) if stat else None,
            "speed_mbps": stat.speed if stat else None,
            "mtu": stat.mtu if stat else None,
            "ipv4": [],
            "ipv6": [],
            "mac": [],
        }
        for addr in addr_list:
            family_text = str(addr.family)
            if addr.family == socket.AF_INET:
                item["ipv4"].append(
                    {
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    }
                )
            elif addr.family == socket.AF_INET6:
                item["ipv6"].append(
                    {
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast,
                    }
                )
            elif "AF_LINK" in family_text or "AF_PACKET" in family_text:
                item["mac"].append(addr.address)
        interfaces.append(item)
    return interfaces


def get_global_ipv6_addresses(interfaces: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    for iface in interfaces:
        if iface.get("is_up") is False:
            continue
        for entry in iface.get("ipv6", []):
            raw = normalize_ip_literal(entry["address"])
            ip = safe_ip(raw)
            if ip and ip.version == 6 and ip.is_global:
                result.append(raw)
    return result


def get_primary_ipv4_candidate(interfaces: list[dict[str, Any]], preferred: str | None = None) -> dict[str, str] | None:
    for iface in interfaces:
        if preferred and iface["name"] != preferred:
            continue
        if iface.get("is_up") is False:
            continue
        for entry in iface.get("ipv4", []):
            ip = safe_ip(entry["address"])
            if not ip or ip.is_loopback or ip.is_link_local:
                continue
            return {
                "interface": iface["name"],
                "address": entry["address"],
                "netmask": entry.get("netmask") or "",
                "broadcast": entry.get("broadcast") or "",
            }
    return None


def interface_check(report: dict[str, Any]) -> list[dict[str, Any]]:
    interfaces = collect_interfaces()
    if not interfaces:
        add_check(
            report,
            "Interface inventory",
            "WARN",
            "Unable to collect interface details because psutil is not available.",
            recommendations=["Install psutil for richer local interface inventory."],
        )
        return []

    up = [iface for iface in interfaces if iface.get("is_up")]
    ipv4_count = sum(len(iface.get("ipv4", [])) for iface in up)
    global_v6 = get_global_ipv6_addresses(interfaces)
    apipa = []
    low_mtu = []
    for iface in up:
        mtu = iface.get("mtu")
        if mtu is not None and mtu < 1280:
            low_mtu.append(f"{iface['name']} mtu={mtu}")
        for entry in iface.get("ipv4", []):
            ip = safe_ip(entry["address"])
            if ip and ip.is_link_local:
                apipa.append(f"{iface['name']} {entry['address']}")

    status = "OK"
    recommendations: list[str] = []
    if not up:
        status = "FAIL"
        recommendations.append("No active network interface was found.")
    elif ipv4_count == 0 and not global_v6:
        status = "FAIL"
        recommendations.append("No usable IPv4 address and no global IPv6 address were found.")
    elif apipa or low_mtu:
        status = "WARN"
        if apipa:
            recommendations.append("169.254.x.x address found; DHCP may have failed on that interface.")
        if low_mtu:
            recommendations.append("MTU below 1280 can break IPv6 and some tunnels; verify adapter or VPN settings.")

    highlights = []
    for iface in interfaces:
        v4 = ", ".join(entry["address"] for entry in iface.get("ipv4", [])) or "-"
        v6 = ", ".join(normalize_ip_literal(entry["address"]) for entry in iface.get("ipv6", [])) or "-"
        state = "up" if iface.get("is_up") else "down"
        highlights.append(f"{iface['name']} [{state}] IPv4={v4} IPv6={v6}")

    add_check(
        report,
        "Interface inventory",
        status,
        f"{len(up)} active interface(s), IPv4 addresses={ipv4_count}, global IPv6={len(global_v6)}.",
        {
            "interfaces": interfaces,
            "global_ipv6": global_v6,
            "apipa": apipa,
            "low_mtu": low_mtu,
            "highlights": highlights,
        },
        recommendations,
    )
    return interfaces


def parse_powershell_json(stdout: str) -> Any:
    if not stdout.strip():
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def collect_routes() -> dict[str, Any]:
    routes: dict[str, Any] = {"ipv4_default": [], "ipv6_default": [], "raw": []}
    if is_windows():
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps:
            for family, dest in [("ipv4_default", "0.0.0.0/0"), ("ipv6_default", "::/0")]:
                cmd = [
                    ps,
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-NetRoute -DestinationPrefix "
                        f"'{dest}' | Select-Object InterfaceAlias,NextHop,RouteMetric,InterfaceMetric "
                        "| ConvertTo-Json -Compress"
                    ),
                ]
                result = run_cmd(cmd, timeout=12)
                routes["raw"].append(result)
                data = parse_powershell_json(result["stdout"])
                if isinstance(data, dict):
                    routes[family].append(data)
                elif isinstance(data, list):
                    routes[family].extend(data)
    elif is_linux():
        for family, command in [
            ("ipv4_default", ["ip", "-4", "route", "show", "default"]),
            ("ipv6_default", ["ip", "-6", "route", "show", "default"]),
        ]:
            result = run_cmd(command, timeout=8)
            routes["raw"].append(result)
            if result["returncode"] == 0:
                for line in result["stdout"].splitlines():
                    entry = {"raw": line}
                    via = re.search(r"\bvia\s+(\S+)", line)
                    dev = re.search(r"\bdev\s+(\S+)", line)
                    metric = re.search(r"\bmetric\s+(\d+)", line)
                    if via:
                        entry["next_hop"] = via.group(1)
                    if dev:
                        entry["interface"] = dev.group(1)
                    if metric:
                        entry["metric"] = int(metric.group(1))
                    routes[family].append(entry)
    return routes


def route_check(report: dict[str, Any]) -> dict[str, Any]:
    routes = collect_routes()
    v4 = routes.get("ipv4_default") or []
    v6 = routes.get("ipv6_default") or []
    status = "OK"
    recommendations: list[str] = []
    if not v4 and not v6:
        status = "FAIL"
        recommendations.append("No default route was found. Check gateway, DHCP, PPPoE, VPN, or static route settings.")
    elif not v4:
        status = "WARN"
        recommendations.append("No IPv4 default route was found.")
    elif len(v4) > 1:
        status = "WARN"
        recommendations.append("Multiple IPv4 default routes exist; wrong route metrics can cause intermittent access.")
    if len(v6) > 1 and status != "FAIL":
        status = "WARN"
        recommendations.append("Multiple IPv6 default routes exist; verify router advertisements and VPN metrics.")
    highlights = [f"IPv4 default routes: {len(v4)}", f"IPv6 default routes: {len(v6)}"]
    add_check(
        report,
        "Default route",
        status,
        f"IPv4 default={len(v4)}, IPv6 default={len(v6)}.",
        {"routes": routes, "highlights": highlights},
        recommendations,
    )
    return routes


def parse_endpoint(value: str, default_port: int = 443) -> tuple[str, int, str]:
    label = value
    if "=" in value:
        label, value = value.split("=", 1)
    value = value.strip()
    if value.startswith("["):
        host, rest = value[1:].split("]", 1)
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port, label
    if value.count(":") > 1:
        return value, default_port, label
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text), label
    return value, default_port, label


def tcp_probe(host: str, port: int, family: socket.AddressFamily, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
        "ok": False,
    }
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        result.update({"error": f"resolve failed: {exc}", "duration_ms": monotonic_ms(started)})
        return result
    errors = []
    for info in infos:
        af, socktype, proto, _canon, sockaddr = info
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            result.update(
                {
                    "ok": True,
                    "remote": sockaddr[0],
                    "local": sock.getsockname()[0],
                    "duration_ms": monotonic_ms(started),
                }
            )
            return result
        except OSError as exc:
            errors.append(str(exc))
        finally:
            sock.close()
    result.update({"error": "; ".join(errors[-3:]), "duration_ms": monotonic_ms(started)})
    return result


def system_resolve(host: str, family: socket.AddressFamily, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    result = {"host": host, "family": "IPv6" if family == socket.AF_INET6 else "IPv4", "ok": False}
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        addrs = sorted({info[4][0] for info in infos})
        result.update({"ok": bool(addrs), "addresses": addrs, "duration_ms": monotonic_ms(started)})
    except Exception as exc:
        result.update({"error": str(exc), "duration_ms": monotonic_ms(started)})
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return result


def connectivity_check(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    timeout = float(getattr(args, "timeout", 3.0))
    v4_targets = DEFAULT_V4_TARGETS.copy()
    v6_targets = DEFAULT_V6_TARGETS.copy()
    for item in getattr(args, "target_v4", None) or []:
        v4_targets.append(parse_endpoint(item))
    for item in getattr(args, "target_v6", None) or []:
        v6_targets.append(parse_endpoint(item))

    tcp_results = []
    for host, port, label in v4_targets:
        item = tcp_probe(host, port, socket.AF_INET, timeout)
        item["label"] = label
        tcp_results.append(item)
    for host, port, label in v6_targets:
        item = tcp_probe(host, port, socket.AF_INET6, timeout)
        item["label"] = label
        tcp_results.append(item)

    resolve_results = []
    for name in DEFAULT_DNS_TEST_NAMES:
        resolve_results.append(system_resolve(name, socket.AF_INET, timeout))
        resolve_results.append(system_resolve(name, socket.AF_INET6, timeout))

    v4_ok = any(item["ok"] for item in tcp_results if item["family"] == "IPv4")
    v6_ok = any(item["ok"] for item in tcp_results if item["family"] == "IPv6")
    dns_v4_ok = any(item["ok"] for item in resolve_results if item["family"] == "IPv4")
    dns_v6_ok = any(item["ok"] for item in resolve_results if item["family"] == "IPv6")

    status = "OK"
    recommendations: list[str] = []
    if not v4_ok and not v6_ok:
        status = "FAIL"
        recommendations.append("No IPv4 or IPv6 TCP target was reachable. Check link state, default gateway, firewall, or upstream outage.")
    elif not v4_ok:
        status = "WARN"
        recommendations.append("IPv4 connectivity failed while IPv6 had at least one success.")
    elif not v6_ok:
        status = "WARN"
        recommendations.append("IPv6 outbound connectivity failed or is not provisioned.")
    if not dns_v4_ok and not dns_v6_ok:
        status = "FAIL" if status == "FAIL" else "WARN"
        recommendations.append("System DNS resolution failed for both A and AAAA records.")

    highlights = []
    for item in tcp_results:
        outcome = "ok" if item["ok"] else f"fail ({item.get('error', 'unknown')})"
        highlights.append(f"{item['family']} {item['label']} {item['host']}:{item['port']} {outcome}")
    for item in resolve_results:
        outcome = ", ".join(item.get("addresses", [])) if item["ok"] else item.get("error", "fail")
        highlights.append(f"DNS {item['family']} {item['host']}: {outcome}")

    add_check(
        report,
        "Connectivity",
        status,
        f"IPv4 outbound={'ok' if v4_ok else 'failed'}, IPv6 outbound={'ok' if v6_ok else 'failed'}, DNS resolve={'ok' if (dns_v4_ok or dns_v6_ok) else 'failed'}.",
        {"tcp": tcp_results, "resolve": resolve_results, "highlights": highlights},
        recommendations,
    )
    return {"tcp": tcp_results, "resolve": resolve_results}


def port_ping_check(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    timeout = float(getattr(args, "timeout", 3.0))
    host = getattr(args, "host", None) or "example.com"
    port = int(getattr(args, "port", 443))
    family = (getattr(args, "family", "both") or "both").lower()
    count = max(1, min(20, int(getattr(args, "count", 3))))
    targets = [parse_endpoint(item, port) for item in (getattr(args, "target", None) or [])]
    if not targets:
        targets = [(host, port, f"{host}:{port}")]

    tcp_results: list[dict[str, Any]] = []
    stats: dict[tuple[str, str, int], dict[str, Any]] = {}

    def record(item: dict[str, Any]) -> None:
        tcp_results.append(item)
        key = (item["family"], item["host"], item["port"])
        bucket = stats.setdefault(
            key,
            {
                "family": item["family"],
                "host": item["host"],
                "port": item["port"],
                "attempts": 0,
                "successes": 0,
                "total_ms": 0,
                "remotes": set(),
                "last_error": "",
            },
        )
        bucket["attempts"] += 1
        if item["ok"]:
            bucket["successes"] += 1
            bucket["total_ms"] += int(item.get("duration_ms", 0))
            if item.get("remote"):
                bucket["remotes"].add(item["remote"])
        else:
            bucket["last_error"] = item.get("error", "unknown")

    for target_host, target_port, label in targets:
        for attempt in range(count):
            if family in {"both", "ipv4", "4"}:
                item = tcp_probe(target_host, target_port, socket.AF_INET, timeout)
                item.update({"label": label, "attempt": attempt + 1})
                record(item)
            if family in {"both", "ipv6", "6"}:
                item = tcp_probe(target_host, target_port, socket.AF_INET6, timeout)
                item.update({"label": label, "attempt": attempt + 1})
                record(item)

    highlights: list[str] = []
    for bucket in stats.values():
        avg = int(bucket["total_ms"] / bucket["successes"]) if bucket["successes"] else 0
        line = f"{bucket['family']} {bucket['host']}:{bucket['port']} success={bucket['successes']}/{bucket['attempts']}"
        if bucket["successes"]:
            line += f" avg={avg}ms"
            if bucket["remotes"]:
                line += f" remote={','.join(sorted(bucket['remotes']))}"
        elif bucket["last_error"]:
            line += f" last_error={bucket['last_error']}"
        highlights.append(line)
    for item in tcp_results:
        outcome = f"ok {item.get('duration_ms', 0)}ms" if item["ok"] else f"fail ({item.get('error', 'unknown')})"
        highlights.append(f"{item['family']} {item['host']}:{item['port']} attempt {item['attempt']}/{count} {outcome}")

    attempts = len(tcp_results)
    successes = sum(1 for item in tcp_results if item["ok"])
    reachable_groups = sum(1 for bucket in stats.values() if bucket["successes"] > 0)
    recommendations: list[str] = []
    if attempts == 0:
        status = "FAIL"
        summary = "No TCP port probe was executed."
        recommendations.append("Check --family, --host, --port, and --target arguments.")
    elif successes == 0:
        status = "FAIL"
        summary = "TCP port unreachable over selected address family."
        recommendations.append("Check DNS records, firewall policy, service listener, route, and whether the target supports the selected IP family.")
    elif reachable_groups < len(stats) or successes < attempts:
        status = "WARN"
        summary = "TCP port partially reachable."
        recommendations.append("One address family or one attempt failed. Compare IPv4/IPv6 DNS, firewall, ISP filtering, and service bind addresses.")
    else:
        status = "OK"
        summary = "TCP port reachable over selected address family."

    add_check(
        report,
        "Port ping",
        status,
        summary,
        {
            "family": family,
            "count": count,
            "timeout_seconds": timeout,
            "targets": len(targets),
            "attempts": attempts,
            "successes": successes,
            "tcp": tcp_results,
            "highlights": highlights,
        },
        recommendations,
    )
    return {"tcp": tcp_results}


def encode_dns_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    out = bytearray()
    for part in parts:
        raw = part.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {part}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset
    seen = set()
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name exceeds packet length")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("DNS compression loop")
            seen.add(pointer)
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        raw_label = packet[offset : offset + length]
        try:
            label = raw_label.decode("idna")
        except UnicodeError:
            label = raw_label.decode("ascii", errors="replace")
        labels.append(label)
        offset += length
    return ".".join(labels), (original_offset + 2 if jumped else offset)


def parse_dns_response(packet: bytes) -> dict[str, Any]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        _qname, offset = read_dns_name(packet, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        name, offset = read_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlen]
        offset += rdlen
        text = None
        if rtype == 1 and rdlen == 4:
            text = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and rdlen == 16:
            text = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            with contextlib.suppress(Exception):
                text, _ = read_dns_name(packet, offset - rdlen)
        answers.append({"name": name, "type": rtype, "class": rclass, "ttl": ttl, "data": text})
    return {
        "id": qid,
        "rcode": rcode,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "answers": answers,
    }


def direct_dns_query(server: str, name: str, qtype: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    query_id = random.randint(0, 65535)
    packet = (
        struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        + encode_dns_name(name)
        + struct.pack("!HH", qtype, 1)
    )
    result: dict[str, Any] = {
        "server": server,
        "name": name,
        "qtype": "AAAA" if qtype == 28 else "A",
        "ok": False,
    }
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, peer = sock.recvfrom(4096)
        parsed = parse_dns_response(data)
        result.update(
            {
                "ok": parsed["rcode"] == 0,
                "peer": peer[0],
                "duration_ms": monotonic_ms(started),
                "rcode": parsed["rcode"],
                "answers": parsed["answers"],
                "answer_count": parsed["answer_count"],
            }
        )
    except Exception as exc:
        result.update({"error": str(exc), "duration_ms": monotonic_ms(started)})
    finally:
        sock.close()
    return result


def read_system_dns() -> dict[str, Any]:
    info: dict[str, Any] = {"servers": [], "raw": []}
    if is_windows():
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps:
            cmd = [
                ps,
                "-NoProfile",
                "-Command",
                (
                    "Get-DnsClientServerAddress | "
                    "Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress"
                ),
            ]
            result = run_cmd(cmd, timeout=12)
            info["raw"].append(result)
            data = parse_powershell_json(result["stdout"])
            rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
            for row in rows:
                for server in row.get("ServerAddresses") or []:
                    server = str(server)
                    if server and server not in info["servers"]:
                        info["servers"].append(server)
    else:
        path = "/etc/resolv.conf"
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            info["raw"].append({"path": path, "content": text})
            for line in text.splitlines():
                match = re.match(r"^\s*nameserver\s+(\S+)", line)
                if match and match.group(1) not in info["servers"]:
                    info["servers"].append(match.group(1))
        if shutil.which("resolvectl"):
            result = run_cmd(["resolvectl", "dns"], timeout=8)
            info["raw"].append(result)
            for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{3,}", result["stdout"]):
                ip = safe_ip(token)
                if ip and token not in info["servers"]:
                    info["servers"].append(token)
    return info


def dns_check(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    timeout = float(getattr(args, "timeout", 3.0))
    provider = getattr(args, "provider", None) or "cloudflare"
    servers: list[str] = []
    if provider in DNS_PROVIDERS:
        servers.extend(DNS_PROVIDERS[provider]["ipv4"])
        servers.extend(DNS_PROVIDERS[provider]["ipv6"])
    for server in getattr(args, "dns_server", None) or []:
        if server not in servers:
            servers.append(server)
    names = getattr(args, "dns_name", None) or DEFAULT_DNS_TEST_NAMES

    system_dns = read_system_dns()
    direct_results = []
    for server in servers:
        for name in names:
            direct_results.append(direct_dns_query(server, name, 1, timeout))
            direct_results.append(direct_dns_query(server, name, 28, timeout))

    ok_count = sum(1 for item in direct_results if item["ok"])
    system_servers = system_dns.get("servers") or []
    loopback_only = system_servers and all(
        (safe_ip(server) and (safe_ip(server).is_loopback or safe_ip(server).is_link_local))
        for server in system_servers
    )
    status = "OK"
    recommendations: list[str] = []
    if ok_count == 0:
        status = "FAIL"
        recommendations.append("Direct DNS queries to tested resolvers all failed; UDP/53 may be blocked or DNS is intercepted.")
    elif ok_count < max(1, len(direct_results) // 2):
        status = "WARN"
        recommendations.append("Some direct DNS tests failed; compare IPv4/IPv6 resolver reachability and firewall policy.")
    if not system_servers:
        status = "WARN" if status == "OK" else status
        recommendations.append("No system DNS server was detected.")
    elif loopback_only:
        status = "WARN" if status == "OK" else status
        recommendations.append("System DNS points only to local/link-local resolver. Verify that the local DNS proxy is healthy.")

    highlights = [f"System DNS: {', '.join(system_servers) if system_servers else '-'}"]
    for item in direct_results:
        answer_text = []
        for answer in item.get("answers", []):
            if answer.get("data") and answer.get("type") in {1, 28}:
                answer_text.append(answer["data"])
        outcome = ", ".join(answer_text[:3]) if item["ok"] else item.get("error", f"rcode={item.get('rcode')}")
        highlights.append(f"{item['server']} {item['qtype']} {item['name']}: {outcome}")

    add_check(
        report,
        "DNS",
        status,
        f"System DNS servers={len(system_servers)}, direct DNS successes={ok_count}/{len(direct_results)}.",
        {"system_dns": system_dns, "direct": direct_results, "highlights": highlights},
        recommendations,
    )
    return {"system_dns": system_dns, "direct": direct_results}


def resolve_stun_server(host: str, port: int, timeout: float) -> tuple[str, int] | None:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if infos:
            return infos[0][4][0], infos[0][4][1]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return None


def parse_stun_attrs(data: bytes, transaction_id: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise ValueError("short STUN response")
    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    if cookie != 0x2112A442:
        raise ValueError("invalid STUN magic cookie")
    attrs: dict[str, Any] = {"message_type": msg_type, "mapped": None, "xor_mapped": None}
    offset = 20
    end = min(len(data), 20 + msg_len)
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        value = data[offset : offset + attr_len]
        offset += attr_len
        offset += (4 - (attr_len % 4)) % 4
        if attr_type in {0x0001, 0x0020} and len(value) >= 8:
            family = value[1]
            port = struct.unpack("!H", value[2:4])[0]
            addr_bytes = value[4:]
            if attr_type == 0x0020:
                port ^= 0x2112
                if family == 1 and len(addr_bytes) >= 4:
                    mask = struct.pack("!I", 0x2112A442)
                    addr_bytes = bytes(a ^ b for a, b in zip(addr_bytes[:4], mask))
                elif family == 2 and len(addr_bytes) >= 16:
                    mask = struct.pack("!I", 0x2112A442) + transaction_id
                    addr_bytes = bytes(a ^ b for a, b in zip(addr_bytes[:16], mask))
            if family == 1 and len(addr_bytes) >= 4:
                address = socket.inet_ntop(socket.AF_INET, addr_bytes[:4])
            elif family == 2 and len(addr_bytes) >= 16:
                address = socket.inet_ntop(socket.AF_INET6, addr_bytes[:16])
            else:
                continue
            key = "xor_mapped" if attr_type == 0x0020 else "mapped"
            attrs[key] = {"address": address, "port": port}
    return attrs


def stun_binding(sock: socket.socket, server: tuple[str, int], timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    transaction_id = os.urandom(12)
    packet = struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, transaction_id)
    result: dict[str, Any] = {"server": f"{server[0]}:{server[1]}", "ok": False}
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, server)
        data, peer = sock.recvfrom(2048)
        parsed = parse_stun_attrs(data, transaction_id)
        mapped = parsed.get("xor_mapped") or parsed.get("mapped")
        result.update(
            {
                "ok": bool(mapped),
                "peer": f"{peer[0]}:{peer[1]}",
                "mapped": mapped,
                "duration_ms": monotonic_ms(started),
            }
        )
        if not mapped:
            result["error"] = "STUN response did not include mapped address"
    except Exception as exc:
        result.update({"error": str(exc), "duration_ms": monotonic_ms(started)})
    return result


def nat_check(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    timeout = float(getattr(args, "timeout", 3.0))
    servers = []
    for entry in getattr(args, "stun_server", None) or []:
        host, port, _label = parse_endpoint(entry, default_port=19302)
        servers.append((host, port))
    if not servers:
        servers = STUN_SERVERS

    resolved = []
    for host, port in servers:
        endpoint = resolve_stun_server(host, port, timeout)
        if endpoint:
            resolved.append((host, endpoint))
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    local = sock.getsockname()
    try:
        for host, endpoint in resolved:
            item = stun_binding(sock, endpoint, timeout)
            item["host"] = host
            results.append(item)
    finally:
        sock.close()

    mapped = [item["mapped"] for item in results if item.get("ok") and item.get("mapped")]
    unique = {(item["address"], item["port"]) for item in mapped}
    local_ip = safe_ip(local[0])
    public_local = bool(local_ip and not (local_ip.is_private or local_ip.is_loopback or local_ip.is_link_local))

    if not mapped:
        status = "FAIL"
        nat_type = "UDP blocked or STUN unreachable"
        recommendations = ["IPv4 UDP STUN failed. Check UDP filtering, captive portal, VPN, or upstream firewall."]
    elif len(unique) > 1:
        status = "WARN"
        nat_type = "Symmetric NAT / address-port dependent mapping"
        recommendations = [
            "Mapped IPv4 endpoint changed across STUN servers; peer-to-peer inbound UDP will usually need relay/TURN or explicit port forwarding."
        ]
    elif public_local and mapped[0]["address"] == local[0]:
        status = "OK"
        nat_type = "No IPv4 NAT detected / public IPv4"
        recommendations = []
    else:
        status = "OK"
        nat_type = "Endpoint-independent IPv4 NAT mapping (cone-like; filtering not classified)"
        recommendations = [
            "This test classifies mapping behavior. Full-cone vs restricted-cone filtering needs a cooperative STUN server and is reported conservatively."
        ]

    highlights = [f"Local UDP socket: {local[0]}:{local[1]}", f"NAT result: {nat_type}"]
    for item in results:
        mapped_text = item.get("mapped")
        if mapped_text:
            outcome = f"{mapped_text['address']}:{mapped_text['port']}"
        else:
            outcome = item.get("error", "failed")
        highlights.append(f"{item.get('host', item['server'])}: {outcome}")

    add_check(
        report,
        "IPv4 NAT",
        status,
        nat_type,
        {
            "local": {"address": local[0], "port": local[1]},
            "servers": results,
            "unique_mappings": sorted([f"{ip}:{port}" for ip, port in unique]),
            "nat_type": nat_type,
            "highlights": highlights,
        },
        recommendations,
    )
    return {"local": local, "results": results, "nat_type": nat_type}


class TemporaryTcpServer:
    def __init__(self, address: str, port: int, duration: float, token: str):
        self.address = address
        self.port = port
        self.duration = duration
        self.token = token.encode("ascii")
        self.accepted: list[dict[str, Any]] = []
        self.error: str | None = None
        self.bound_port: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            with contextlib.suppress(Exception):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.address, self.port))
            sock.listen(8)
            sock.settimeout(0.5)
            self.bound_port = sock.getsockname()[1]
            self._sock = sock
        except Exception as exc:
            self.error = str(exc)
            return False
        self._thread = threading.Thread(target=self._serve, name="netfix-ipv6-listener", daemon=True)
        self._thread.start()
        return True

    def _serve(self) -> None:
        assert self._sock is not None
        deadline = time.monotonic() + self.duration
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                self.accepted.append({"remote": addr[0], "port": addr[1], "at": local_now()})
                with contextlib.suppress(Exception):
                    conn.sendall(b"NETFIX " + self.token + b"\r\n")

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)


def check_host_tcp_probe(host: str, port: int, timeout: float, max_nodes: int) -> dict[str, Any]:
    started = time.monotonic()
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    query = urllib.parse.urlencode({"host": target, "max_nodes": str(max_nodes)})
    url = f"https://check-host.net/check-tcp?{query}"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"{TOOL_NAME}/{VERSION}"})
    result: dict[str, Any] = {"target": target, "ok": False, "request_url": url}
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        result.update(data)
        request_id = data.get("request_id")
        if not request_id:
            result["error"] = "check-host response did not include request_id"
            return result
        for _ in range(8):
            time.sleep(2)
            result_url = f"https://check-host.net/check-result/{request_id}"
            req = urllib.request.Request(
                result_url,
                headers={"Accept": "application/json", "User-Agent": f"{TOOL_NAME}/{VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                results = json.loads(response.read().decode("utf-8"))
            result["results"] = results
            complete_nodes = {node: value for node, value in results.items() if value is not None}
            successes = []
            failures = []
            for node, value in complete_nodes.items():
                if isinstance(value, list) and value and isinstance(value[0], dict) and not value[0].get("error"):
                    successes.append({"node": node, "result": value[0]})
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    failures.append({"node": node, "error": value[0].get("error")})
            result["successes"] = successes
            result["failures"] = failures
            if successes:
                result["ok"] = True
                break
            if complete_nodes and len(complete_nodes) >= max(1, max_nodes):
                break
        result["duration_ms"] = monotonic_ms(started)
    except Exception as exc:
        result.update({"error": str(exc), "duration_ms": monotonic_ms(started)})
    return result


def ipv6_check(report: dict[str, Any], args: argparse.Namespace, interfaces: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    timeout = float(getattr(args, "timeout", 3.0))
    if interfaces is None:
        interfaces = collect_interfaces()
    global_v6 = get_global_ipv6_addresses(interfaces)
    outbound = []
    for host, port, label in DEFAULT_V6_TARGETS:
        item = tcp_probe(host, port, socket.AF_INET6, timeout)
        item["label"] = label
        outbound.append(item)

    outbound_ok = any(item["ok"] for item in outbound)
    inbound_result: dict[str, Any] = {
        "mode": "external" if not getattr(args, "no_external_inbound", False) else "local-listen-only",
        "ok": False,
    }
    recommendations: list[str] = []
    status = "OK" if outbound_ok else "WARN"
    if not global_v6:
        status = "WARN"
        recommendations.append("No global IPv6 address was detected; inbound IPv6 cannot work without one.")
    elif getattr(args, "no_external_inbound", False):
        inbound_result["skipped"] = "external inbound checker disabled"
        status = "WARN" if status == "OK" else status
        recommendations.append("External IPv6 inbound reachability was not tested because --no-external-inbound was used.")
    else:
        address = getattr(args, "inbound_address", None) or global_v6[0]
        port = int(getattr(args, "inbound_port", 0) or 0)
        duration = float(getattr(args, "inbound_seconds", 22.0))
        token = uuid.uuid4().hex[:12]
        server = TemporaryTcpServer("::", port, duration + 5, token)
        if not server.start():
            inbound_result.update({"error": server.error, "address": address, "port": port})
            status = "WARN"
            recommendations.append("Local IPv6 listener could not be started. Check host firewall or permission policy.")
        else:
            try:
                actual_port = server.bound_port or port
                inbound_result.update({"address": address, "port": actual_port, "token": token})
                probe = check_host_tcp_probe(address, actual_port, timeout, int(getattr(args, "check_host_nodes", 3)))
                inbound_result["external_probe"] = probe
                inbound_result["accepted"] = server.accepted
                inbound_result["ok"] = bool(probe.get("ok") or server.accepted)
                if inbound_result["ok"]:
                    status = "OK" if outbound_ok else "WARN"
                else:
                    status = "WARN"
                    recommendations.append(
                        "IPv6 listener started locally, but no external checker reached it. Check host firewall, router firewall, ISP filtering, and prefix routing."
                    )
            finally:
                server.stop()
                inbound_result["accepted"] = server.accepted

    if not outbound_ok:
        recommendations.append("IPv6 outbound failed. Verify router advertisement, DHCPv6/prefix delegation, firewall, and DNS AAAA reachability.")

    highlights = [f"Global IPv6 addresses: {', '.join(global_v6) if global_v6 else '-'}"]
    for item in outbound:
        outcome = "ok" if item["ok"] else item.get("error", "failed")
        highlights.append(f"IPv6 outbound {item['label']}: {outcome}")
    if inbound_result.get("address"):
        highlights.append(f"IPv6 inbound listener: [{inbound_result['address']}]:{inbound_result['port']}")
    if inbound_result.get("external_probe"):
        probe = inbound_result["external_probe"]
        highlights.append(f"IPv6 inbound external: {'ok' if probe.get('ok') else probe.get('error', 'failed')}")

    add_check(
        report,
        "IPv6 stack",
        status,
        f"Outbound={'ok' if outbound_ok else 'failed'}, inbound={'ok' if inbound_result.get('ok') else 'not verified/failed'}.",
        {
            "global_addresses": global_v6,
            "outbound": outbound,
            "inbound": inbound_result,
            "highlights": highlights,
            "external_probe_source": "https://check-host.net/about/api?lang=en",
        },
        recommendations,
    )
    return {"global_addresses": global_v6, "outbound": outbound, "inbound": inbound_result}


def load_scapy() -> tuple[Any | None, str | None]:
    try:
        import scapy.all as scapy  # type: ignore

        return scapy, None
    except Exception as exc:
        return None, str(exc)


def get_dhcp_message_type(options: list[Any]) -> str | None:
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == "message-type":
            return str(opt[1])
    return None


def get_dhcp_option(options: list[Any], name: str) -> Any:
    for opt in options:
        if isinstance(opt, tuple) and opt and opt[0] == name:
            return opt[1]
    return None


def mac_to_bootp_chaddr(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":")) + b"\x00" * 10


def send_dhcp_discover(scapy: Any, iface: str | None, count: int, interval: float = 0.7) -> int:
    sent = 0
    for _ in range(count):
        mac = str(scapy.RandMAC())
        xid = random.randint(1, 0xFFFFFFFF)
        pkt = (
            scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / scapy.IP(src="0.0.0.0", dst="255.255.255.255")
            / scapy.UDP(sport=68, dport=67)
            / scapy.BOOTP(chaddr=mac_to_bootp_chaddr(mac), xid=xid, flags=0x8000)
            / scapy.DHCP(
                options=[
                    ("message-type", "discover"),
                    ("param_req_list", [1, 3, 6, 15, 51, 54, 58, 59]),
                    "end",
                ]
            )
        )
        scapy.sendp(pkt, iface=iface, verbose=False)
        sent += 1
        time.sleep(interval)
    return sent


def stop_sniffer(sniffer: Any) -> list[Any]:
    try:
        return list(sniffer.stop())
    except Exception:
        with contextlib.suppress(Exception):
            sniffer.stop(join=False)
        return list(getattr(sniffer, "results", []) or [])


def dhcp_check(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    scapy, error = load_scapy()
    if not scapy:
        add_check(
            report,
            "DHCP",
            "SKIP",
            "Packet capture is unavailable because Scapy is not installed or could not be imported.",
            {"error": error},
            ["Install requirements.txt and run as Administrator/root. Windows also needs Npcap with WinPcap-compatible mode."],
        )
        return {"skipped": error}

    seconds = float(getattr(args, "dhcp_seconds", getattr(args, "seconds", 12.0)))
    iface = getattr(args, "interface", None)
    active = bool(getattr(args, "dhcp_active", getattr(args, "active", False)))
    discover_count = int(getattr(args, "discover_count", 2))
    packets: list[Any] = []
    sent = 0
    capture_error = None

    try:
        sniffer = scapy.AsyncSniffer(iface=iface, filter="udp and (port 67 or 68)", store=True)
        sniffer.start()
        time.sleep(0.6)
        if active:
            sent = send_dhcp_discover(scapy, iface, discover_count)
        time.sleep(seconds)
        packets = stop_sniffer(sniffer)
    except Exception as exc:
        capture_error = str(exc)
        with contextlib.suppress(Exception):
            sniffer = scapy.AsyncSniffer(iface=iface, store=True)
            sniffer.start()
            time.sleep(seconds)
            packets = stop_sniffer(sniffer)

    events = []
    server_sources: dict[str, dict[str, Any]] = {}
    type_counts = Counter()
    broadcast_count = 0
    for pkt in packets:
        if not pkt.haslayer(scapy.UDP):
            continue
        udp = pkt[scapy.UDP]
        if int(udp.sport) not in {67, 68} and int(udp.dport) not in {67, 68}:
            continue
        ether = pkt[scapy.Ether] if pkt.haslayer(scapy.Ether) else None
        ip = pkt[scapy.IP] if pkt.haslayer(scapy.IP) else None
        if ether and str(ether.dst).lower() == "ff:ff:ff:ff:ff:ff":
            broadcast_count += 1
        if ip and str(ip.dst) == "255.255.255.255":
            broadcast_count += 1
        msg_type = None
        server_id = None
        if pkt.haslayer(scapy.DHCP):
            options = pkt[scapy.DHCP].options
            msg_type = get_dhcp_message_type(options)
            server_id = get_dhcp_option(options, "server_id")
        if msg_type:
            type_counts[msg_type] += 1
        source_ip = str(ip.src) if ip else None
        source_mac = str(ether.src) if ether else None
        event = {
            "message_type": msg_type,
            "source_ip": source_ip,
            "source_mac": source_mac,
            "destination_ip": str(ip.dst) if ip else None,
            "destination_mac": str(ether.dst) if ether else None,
            "server_id": str(server_id) if server_id else None,
            "sport": int(udp.sport),
            "dport": int(udp.dport),
        }
        events.append(event)
        if msg_type in {"offer", "ack", "nak"} or int(udp.sport) == 67:
            key = str(server_id or source_ip or source_mac)
            if key and key != "None":
                server_sources.setdefault(
                    key,
                    {"server_id": str(server_id) if server_id else None, "source_ips": set(), "source_macs": set(), "packets": 0},
                )
                server_sources[key]["packets"] += 1
                if source_ip:
                    server_sources[key]["source_ips"].add(source_ip)
                if source_mac:
                    server_sources[key]["source_macs"].add(source_mac)

    normalized_servers = []
    for key, value in server_sources.items():
        normalized_servers.append(
            {
                "id": key,
                "server_id": value["server_id"],
                "source_ips": sorted(value["source_ips"]),
                "source_macs": sorted(value["source_macs"]),
                "packets": value["packets"],
            }
        )

    status = "OK"
    recommendations: list[str] = []
    if capture_error:
        status = "WARN"
        recommendations.append("Capture filter failed or packet capture had errors; install Npcap/libpcap and run with elevated privileges.")
    if len(normalized_servers) > 1:
        status = "WARN"
        recommendations.append("Multiple DHCP sources were observed. Verify whether all are authorized; rogue DHCP can break the LAN.")
    if not events:
        status = "WARN"
        recommendations.append("No DHCP packets were captured. Increase --dhcp-seconds or use --dhcp-active from a safe maintenance window.")
    if broadcast_count > max(20, seconds * 5):
        status = "WARN"
        recommendations.append("High DHCP broadcast volume was observed; investigate client loops, relay issues, or DHCP storms.")

    highlights = [
        f"Captured DHCP packets: {len(events)}",
        f"DHCP broadcasts: {broadcast_count}",
        f"Active discover packets sent: {sent}",
        f"DHCP sources: {len(normalized_servers)}",
    ]
    for server in normalized_servers[:8]:
        highlights.append(
            f"DHCP source {server['id']} ips={','.join(server['source_ips']) or '-'} macs={','.join(server['source_macs']) or '-'} packets={server['packets']}"
        )
    if capture_error:
        highlights.append(f"Capture warning: {capture_error}")

    add_check(
        report,
        "DHCP",
        status,
        f"Captured {len(events)} DHCP packet(s), broadcasts={broadcast_count}, DHCP source count={len(normalized_servers)}.",
        {
            "interface": iface,
            "duration_seconds": seconds,
            "active_discover": active,
            "discover_sent": sent,
            "packet_count": len(events),
            "broadcast_count": broadcast_count,
            "message_type_counts": dict(type_counts),
            "servers": normalized_servers,
            "events": events[:500],
            "capture_error": capture_error,
            "highlights": highlights,
        },
        recommendations,
    )
    return {"events": events, "servers": normalized_servers}


def is_broadcast_or_multicast(pkt: Any, scapy: Any) -> bool:
    if pkt.haslayer(scapy.Ether):
        dst = str(pkt[scapy.Ether].dst).lower()
        if dst == "ff:ff:ff:ff:ff:ff" or dst.startswith("01:00:5e") or dst.startswith("33:33"):
            return True
    if pkt.haslayer(scapy.IP):
        dst_ip = safe_ip(str(pkt[scapy.IP].dst))
        if dst_ip and (dst_ip.is_multicast or str(dst_ip) == "255.255.255.255"):
            return True
    if pkt.haslayer(scapy.IPv6):
        dst_v6 = safe_ip(str(pkt[scapy.IPv6].dst))
        if dst_v6 and dst_v6.is_multicast:
            return True
    return False


def get_packet_source_hint(pkt: Any, scapy: Any) -> tuple[str | None, str | None]:
    mac = str(pkt[scapy.Ether].src) if pkt.haslayer(scapy.Ether) else None
    ip = None
    if pkt.haslayer(scapy.ARP):
        ip = str(pkt[scapy.ARP].psrc)
    elif pkt.haslayer(scapy.IP):
        ip = str(pkt[scapy.IP].src)
    elif pkt.haslayer(scapy.IPv6):
        ip = str(pkt[scapy.IPv6].src)
    return ip, mac


def loop_check(report: dict[str, Any], args: argparse.Namespace, interfaces: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    scapy, error = load_scapy()
    if not scapy:
        add_check(
            report,
            "LAN loop and broadcast storm",
            "SKIP",
            "Packet-level loop detection is unavailable because Scapy is not installed or could not be imported.",
            {"error": error},
            ["Install requirements.txt and run as Administrator/root. Windows also needs Npcap."],
        )
        return {"skipped": error}

    if interfaces is None:
        interfaces = collect_interfaces()
    iface = getattr(args, "interface", None)
    local_v4 = get_primary_ipv4_candidate(interfaces, iface)
    seconds = float(getattr(args, "loop_seconds", getattr(args, "seconds", 8.0)))
    probes = int(getattr(args, "loop_probes", getattr(args, "probes", 3)))
    marker = f"NETFIX-LOOP-{uuid.uuid4().hex}".encode("ascii")
    packets: list[Any] = []
    sent = 0
    capture_error = None

    try:
        sniffer = scapy.AsyncSniffer(iface=iface, store=True)
        sniffer.start()
        time.sleep(0.7)
        for idx in range(probes):
            if local_v4 and local_v4.get("broadcast"):
                pkt = (
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    / scapy.IP(src=local_v4["address"], dst=local_v4["broadcast"], ttl=1)
                    / scapy.UDP(sport=39000 + idx, dport=39999)
                    / scapy.Raw(load=marker + f"-{idx}".encode("ascii"))
                )
            else:
                pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / scapy.Raw(load=marker + f"-{idx}".encode("ascii"))
            scapy.sendp(pkt, iface=iface, verbose=False)
            sent += 1
            time.sleep(0.5)
        time.sleep(seconds)
        packets = stop_sniffer(sniffer)
    except Exception as exc:
        capture_error = str(exc)

    marker_hits = []
    broadcast_packets = []
    source_counts: Counter[tuple[str | None, str | None]] = Counter()
    duplicate_payloads: Counter[str] = Counter()
    arp_claims: dict[str, set[str]] = defaultdict(set)
    for pkt in packets:
        raw = bytes(pkt)
        if marker in raw:
            ip, mac = get_packet_source_hint(pkt, scapy)
            marker_hits.append({"source_ip": ip, "source_mac": mac, "summary": pkt.summary()})
        if is_broadcast_or_multicast(pkt, scapy):
            broadcast_packets.append(pkt)
            ip, mac = get_packet_source_hint(pkt, scapy)
            source_counts[(ip, mac)] += 1
            duplicate_payloads[base64.b16encode(raw[:96]).decode("ascii")] += 1
        if pkt.haslayer(scapy.ARP):
            psrc = str(pkt[scapy.ARP].psrc)
            hwsrc = str(pkt[scapy.ARP].hwsrc)
            if psrc and hwsrc:
                arp_claims[psrc].add(hwsrc)

    duplicate_arp = [
        {"ip": ip, "macs": sorted(macs)}
        for ip, macs in arp_claims.items()
        if ip != "0.0.0.0" and len(macs) > 1
    ]
    top_sources = [
        {"source_ip": ip, "source_mac": mac, "packets": count}
        for (ip, mac), count in source_counts.most_common(12)
    ]
    repeated_payloads = sum(1 for _payload, count in duplicate_payloads.items() if count > 3)
    marker_extra = max(0, len(marker_hits) - sent)
    broadcast_rate = len(broadcast_packets) / max(seconds, 1.0)

    status = "OK"
    recommendations: list[str] = []
    if capture_error:
        status = "WARN"
        recommendations.append("Packet capture failed. Run with elevated privileges and verify Npcap/libpcap.")
    if marker_extra > 0:
        status = "WARN"
        recommendations.append("The tool observed more copies of its own broadcast probe than it sent; this is a strong loop/duplication signal.")
    if broadcast_rate > float(getattr(args, "broadcast_threshold", 60.0)):
        status = "WARN"
        recommendations.append("Broadcast/multicast rate is high. Check switch loops, bad NICs, rogue bridges, or STP-disabled access switches.")
    if duplicate_arp:
        status = "WARN"
        recommendations.append("The same IP was advertised by multiple MAC addresses; investigate duplicate IP or ARP spoofing.")
    if not packets:
        status = "WARN"
        recommendations.append("No packets were captured. Select --interface or run with packet capture privileges.")

    highlights = [
        f"Packets captured: {len(packets)}",
        f"Broadcast/multicast packets: {len(broadcast_packets)} ({broadcast_rate:.1f}/s)",
        f"Loop probes sent: {sent}",
        f"Probe marker sightings: {len(marker_hits)}",
        f"Repeated broadcast payload fingerprints: {repeated_payloads}",
    ]
    for source in top_sources[:8]:
        highlights.append(
            f"Top broadcast source ip={source['source_ip'] or '-'} mac={source['source_mac'] or '-'} packets={source['packets']}"
        )
    for conflict in duplicate_arp[:5]:
        highlights.append(f"ARP conflict hint {conflict['ip']}: {', '.join(conflict['macs'])}")
    if capture_error:
        highlights.append(f"Capture error: {capture_error}")

    add_check(
        report,
        "LAN loop and broadcast storm",
        status,
        f"Broadcast/multicast={len(broadcast_packets)} over {seconds:.1f}s, loop probe extra copies={marker_extra}.",
        {
            "interface": iface,
            "duration_seconds": seconds,
            "probes_sent": sent,
            "marker_hits": marker_hits[:50],
            "marker_extra_copies": marker_extra,
            "broadcast_count": len(broadcast_packets),
            "broadcast_rate_per_second": broadcast_rate,
            "top_sources": top_sources,
            "duplicate_arp_claims": duplicate_arp,
            "repeated_payload_fingerprint_count": repeated_payloads,
            "capture_error": capture_error,
            "local_ipv4_probe": local_v4,
            "highlights": highlights,
        },
        recommendations,
    )
    return {"top_sources": top_sources, "marker_hits": marker_hits, "duplicate_arp": duplicate_arp}


def internal_health_check(report: dict[str, Any]) -> None:
    issues = []
    recommendations = []
    checks = {check["name"]: check for check in report["checks"]}

    iface = checks.get("Interface inventory", {})
    for apipa in iface.get("details", {}).get("apipa", []) or []:
        issues.append(f"APIPA/link-local IPv4: {apipa}")
    for low in iface.get("details", {}).get("low_mtu", []) or []:
        issues.append(f"Low MTU: {low}")

    route = checks.get("Default route", {})
    routes = route.get("details", {}).get("routes", {})
    if len(routes.get("ipv4_default", []) or []) > 1:
        issues.append("Multiple IPv4 default routes")
    if len(routes.get("ipv6_default", []) or []) > 1:
        issues.append("Multiple IPv6 default routes")

    dhcp = checks.get("DHCP", {})
    dhcp_servers = dhcp.get("details", {}).get("servers", []) or []
    if len(dhcp_servers) > 1:
        issues.append(f"Multiple DHCP sources: {len(dhcp_servers)}")
        recommendations.append("Keep only authorized DHCP services on the VLAN or configure DHCP snooping on switches.")

    loop = checks.get("LAN loop and broadcast storm", {})
    loop_details = loop.get("details", {})
    if loop_details.get("marker_extra_copies", 0) > 0:
        issues.append("Broadcast loop probe returned extra copies")
        recommendations.append("Trace the top broadcast MAC/IP sources to switch CAM tables and verify STP/loop guard.")
    if loop_details.get("duplicate_arp_claims"):
        issues.append("Duplicate ARP claims")
        recommendations.append("Resolve duplicate static IPs or investigate ARP spoofing/security software.")

    dns = checks.get("DNS", {})
    system_servers = dns.get("details", {}).get("system_dns", {}).get("servers", []) or []
    if system_servers and len(system_servers) != len(set(system_servers)):
        issues.append("Duplicate DNS server entries")

    status = "OK" if not issues else "WARN"
    if not recommendations and issues:
        recommendations.append("Review the detailed checks above; focus first on DHCP, routes, DNS, and broadcast sources.")
    add_check(
        report,
        "LAN health summary",
        status,
        "No obvious LAN-side issue was detected." if not issues else f"{len(issues)} LAN-side issue hint(s) detected.",
        {"issues": issues, "highlights": issues[:12]},
        recommendations,
    )


def build_dns_commands(provider: str | None, custom_dns: list[str], interface: str | None) -> tuple[list[list[str]], list[str]]:
    servers: list[str] = []
    if provider:
        if provider not in DNS_PROVIDERS:
            raise ValueError(f"Unknown DNS provider: {provider}")
        servers.extend(DNS_PROVIDERS[provider]["ipv4"])
        servers.extend(DNS_PROVIDERS[provider]["ipv6"])
    servers.extend(custom_dns or [])
    servers = [server for idx, server in enumerate(servers) if server and server not in servers[:idx]]
    if not servers:
        return [], []

    commands: list[list[str]] = []
    notes: list[str] = []
    v4_servers = [server for server in servers if safe_ip(server) and safe_ip(server).version == 4]
    v6_servers = [server for server in servers if safe_ip(server) and safe_ip(server).version == 6]
    if is_windows():
        if not interface:
            notes.append("Windows DNS replacement needs --interface with the adapter alias, for example: --interface Ethernet")
            return [], notes
        if v4_servers:
            commands.append(["netsh", "interface", "ip", "set", "dns", f"name={interface}", "static", v4_servers[0], "primary"])
            for index, server in enumerate(v4_servers[1:], start=2):
                commands.append(["netsh", "interface", "ip", "add", "dns", f"name={interface}", server, f"index={index}"])
        if v6_servers:
            commands.append(["netsh", "interface", "ipv6", "set", "dnsservers", interface, "static", v6_servers[0], "primary"])
            for index, server in enumerate(v6_servers[1:], start=2):
                commands.append(["netsh", "interface", "ipv6", "add", "dnsservers", interface, server, f"index={index}"])
    elif is_linux():
        nmcli = shutil.which("nmcli")
        resolvectl = shutil.which("resolvectl")
        if nmcli:
            if interface:
                commands.append(["nmcli", "device", "modify", interface, "ipv4.dns", ",".join(v4_servers), "ipv4.ignore-auto-dns", "yes"])
                if v6_servers:
                    commands.append(["nmcli", "device", "modify", interface, "ipv6.dns", ",".join(v6_servers), "ipv6.ignore-auto-dns", "yes"])
                commands.append(["nmcli", "device", "reapply", interface])
            else:
                notes.append("Linux DNS replacement with nmcli is safer with --interface DEVICE; no command generated without it.")
        elif resolvectl:
            target = interface or "default"
            commands.append(["resolvectl", "dns", target, *(v4_servers + v6_servers)])
            commands.append(["resolvectl", "flush-caches"])
        else:
            notes.append("Neither nmcli nor resolvectl was found. Edit /etc/resolv.conf or your network manager profile manually.")
    else:
        notes.append("DNS replacement is implemented for Windows and Linux only.")
    return commands, notes


def build_repair_commands(args: argparse.Namespace) -> tuple[list[list[str]], list[str]]:
    commands: list[list[str]] = []
    notes: list[str] = []
    if getattr(args, "flush_dns", False):
        if is_windows():
            commands.append(["ipconfig", "/flushdns"])
        elif is_linux():
            if shutil.which("resolvectl"):
                commands.append(["resolvectl", "flush-caches"])
            elif shutil.which("systemd-resolve"):
                commands.append(["systemd-resolve", "--flush-caches"])
            else:
                notes.append("No systemd DNS cache tool found; flush browser/application DNS caches if needed.")
    if getattr(args, "reset_stack", False):
        if is_windows():
            commands.extend(
                [
                    ["netsh", "winsock", "reset"],
                    ["netsh", "int", "ip", "reset"],
                    ["netsh", "int", "ipv6", "reset"],
                ]
            )
            notes.append("Windows stack reset usually requires reboot.")
        elif is_linux():
            if shutil.which("ip"):
                commands.append(["ip", "route", "flush", "cache"])
            notes.append("Linux full network resets are distro-specific; restart NetworkManager/systemd-networkd only during a safe maintenance window.")
    dns_commands, dns_notes = build_dns_commands(
        getattr(args, "set_dns", None),
        getattr(args, "custom_dns", None) or [],
        getattr(args, "interface", None),
    )
    commands.extend(dns_commands)
    notes.extend(dns_notes)
    return commands, notes


def repair_command(report: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    commands, notes = build_repair_commands(args)
    apply_changes = bool(getattr(args, "apply", False))
    results = []
    recommendations = []
    if commands and not apply_changes:
        recommendations.append("Dry run only. Re-run with --apply to execute these commands.")
    if apply_changes and commands and not is_admin():
        recommendations.append("Some commands may fail without Administrator/root privileges.")
    if apply_changes:
        for cmd in commands:
            results.append(run_cmd(cmd, timeout=30))

    status = "OK"
    if not commands and not notes:
        status = "INFO"
        notes.append("No repair action was requested.")
    elif apply_changes and any(item["returncode"] != 0 for item in results):
        status = "WARN"
        recommendations.append("At least one repair command failed; inspect command results.")
    elif not apply_changes:
        status = "INFO"

    highlights = []
    for cmd in commands:
        highlights.append("Command: " + " ".join(cmd))
    for note in notes:
        highlights.append("Note: " + note)
    for result in results:
        highlights.append(f"Ran rc={result['returncode']}: {' '.join(result['command'])}")

    add_check(
        report,
        "Repair",
        status,
        "Executed requested repair commands." if apply_changes else "Prepared repair commands without changing the system.",
        {"apply": apply_changes, "commands": commands, "notes": notes, "results": results, "highlights": highlights},
        recommendations,
    )
    return {"commands": commands, "results": results}


def run_scan(args: argparse.Namespace) -> int:
    report = make_report("scan")
    interfaces = interface_check(report)
    route_check(report)
    connectivity_check(report, args)
    dns_check(report, args)
    nat_check(report, args)
    ipv6_check(report, args, interfaces)
    if getattr(args, "skip_packet", False):
        add_check(
            report,
            "Packet-level LAN checks",
            "SKIP",
            "DHCP and LAN loop packet checks were skipped by --skip-packet.",
        )
    else:
        dhcp_check(report, args)
        loop_check(report, args, interfaces)
    internal_health_check(report)
    return emit_report(report, args)


def run_single(command: str, fn: Any, args: argparse.Namespace) -> int:
    report = make_report(command)
    if command in {"dhcp", "loop", "ipv6"}:
        interfaces = interface_check(report) if command in {"loop", "ipv6"} else None
        if command == "loop":
            fn(report, args, interfaces)
        elif command == "ipv6":
            fn(report, args, interfaces)
        else:
            fn(report, args)
    else:
        fn(report, args)
    return emit_report(report, args)


def add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print JSON instead of the text summary.")
    parser.add_argument("--output", help="Write full JSON report to this path.")
    parser.add_argument("--strict-exit", action="store_true", help="Return non-zero when WARN or FAIL is present.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Network timeout in seconds.")


def add_scan_args(parser: argparse.ArgumentParser) -> None:
    add_output_args(parser)
    parser.add_argument("--interface", help="Preferred interface name for packet checks and DNS repair commands.")
    parser.add_argument("--target-v4", action="append", help="Extra IPv4 TCP target, format label=host:port or host:port.")
    parser.add_argument("--target-v6", action="append", help="Extra IPv6 TCP target, format label=[addr]:port or addr.")
    parser.add_argument("--provider", choices=sorted(DNS_PROVIDERS), default="cloudflare", help="DNS provider used for direct DNS tests.")
    parser.add_argument("--dns-server", action="append", help="Extra DNS server to query directly.")
    parser.add_argument("--dns-name", action="append", help="Domain name to test via DNS.")
    parser.add_argument("--stun-server", action="append", help="Extra STUN server host:port for IPv4 NAT mapping detection.")
    parser.add_argument("--no-external-inbound", action="store_true", help="Skip online IPv6 inbound TCP probe.")
    parser.add_argument("--inbound-address", help="Global IPv6 address to expose for inbound test. Defaults to first detected global IPv6.")
    parser.add_argument("--inbound-port", type=int, default=0, help="TCP port for temporary IPv6 inbound listener; 0 chooses a random port.")
    parser.add_argument("--inbound-seconds", type=float, default=22.0, help="How long to keep the temporary IPv6 listener alive.")
    parser.add_argument("--check-host-nodes", type=int, default=3, help="Number of check-host.net nodes for external IPv6 inbound test.")
    parser.add_argument("--skip-packet", action="store_true", help="Skip DHCP and LAN loop packet capture checks.")
    parser.add_argument("--dhcp-seconds", type=float, default=12.0, help="Passive DHCP capture duration.")
    parser.add_argument("--dhcp-active", action="store_true", help="Send DHCP Discover probes during DHCP capture.")
    parser.add_argument("--discover-count", type=int, default=2, help="DHCP Discover probe count when --dhcp-active is used.")
    parser.add_argument("--loop-seconds", type=float, default=8.0, help="LAN loop capture duration after active probes.")
    parser.add_argument("--loop-probes", type=int, default=3, help="Broadcast loop probe count.")
    parser.add_argument("--broadcast-threshold", type=float, default=60.0, help="Broadcast/multicast packets per second threshold.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netfix",
        description="Cross-platform network detection and conservative repair helper.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run the full diagnostic suite.")
    add_scan_args(scan)

    connectivity = sub.add_parser("connectivity", help="Check IPv4/IPv6 TCP reachability and system DNS resolution.")
    add_output_args(connectivity)
    connectivity.add_argument("--target-v4", action="append")
    connectivity.add_argument("--target-v6", action="append")

    port = sub.add_parser("port", help="TCP port ping over IPv4 and/or IPv6.")
    add_output_args(port)
    port.add_argument("--host", default="example.com")
    port.add_argument("--port", type=int, default=443)
    port.add_argument("--target", action="append", help="Target in host:port format; IPv6 can use [addr]:port.")
    port.add_argument("--family", choices=["both", "ipv4", "ipv6", "4", "6"], default="both")
    port.add_argument("--count", type=int, default=3)

    portping = sub.add_parser("portping", help="Alias for port.")
    add_output_args(portping)
    portping.add_argument("--host", default="example.com")
    portping.add_argument("--port", type=int, default=443)
    portping.add_argument("--target", action="append", help="Target in host:port format; IPv6 can use [addr]:port.")
    portping.add_argument("--family", choices=["both", "ipv4", "ipv6", "4", "6"], default="both")
    portping.add_argument("--count", type=int, default=3)

    dns = sub.add_parser("dns", help="Check system DNS and direct resolver behavior.")
    add_output_args(dns)
    dns.add_argument("--provider", choices=sorted(DNS_PROVIDERS), default="cloudflare")
    dns.add_argument("--dns-server", action="append")
    dns.add_argument("--dns-name", action="append")

    nat = sub.add_parser("nat", help="Detect IPv4 NAT mapping behavior using STUN.")
    add_output_args(nat)
    nat.add_argument("--stun-server", action="append")

    ipv6 = sub.add_parser("ipv6", help="Check IPv6 outbound and inbound reachability.")
    add_output_args(ipv6)
    ipv6.add_argument("--no-external-inbound", action="store_true")
    ipv6.add_argument("--inbound-address")
    ipv6.add_argument("--inbound-port", type=int, default=0)
    ipv6.add_argument("--inbound-seconds", type=float, default=22.0)
    ipv6.add_argument("--check-host-nodes", type=int, default=3)

    dhcp = sub.add_parser("dhcp", help="Capture DHCP broadcasts and identify DHCP sources.")
    add_output_args(dhcp)
    dhcp.add_argument("--interface")
    dhcp.add_argument("--seconds", type=float, default=12.0)
    dhcp.add_argument("--active", action="store_true")
    dhcp.add_argument("--discover-count", type=int, default=2)

    loop = sub.add_parser("loop", help="Probe and capture broadcast-loop or storm hints.")
    add_output_args(loop)
    loop.add_argument("--interface")
    loop.add_argument("--seconds", type=float, default=8.0)
    loop.add_argument("--probes", type=int, default=3)
    loop.add_argument("--broadcast-threshold", type=float, default=60.0)

    repair = sub.add_parser("repair", help="Prepare or apply conservative repair commands.")
    add_output_args(repair)
    repair.add_argument("--interface", help="Adapter alias/device for DNS changes.")
    repair.add_argument("--set-dns", choices=sorted(DNS_PROVIDERS), help="Replace DNS with a known provider.")
    repair.add_argument("--custom-dns", action="append", help="Extra custom DNS server to set.")
    repair.add_argument("--flush-dns", action="store_true")
    repair.add_argument("--reset-stack", action="store_true")
    repair.add_argument("--apply", action="store_true", help="Actually execute repair commands.")

    return parser


def dispatch(args: argparse.Namespace) -> int:
    command = args.command or "scan"
    if command == "scan":
        return run_scan(args)
    if command == "connectivity":
        return run_single("connectivity", connectivity_check, args)
    if command in {"port", "portping"}:
        return run_single("port", port_ping_check, args)
    if command == "dns":
        return run_single("dns", dns_check, args)
    if command == "nat":
        return run_single("nat", nat_check, args)
    if command == "ipv6":
        return run_single("ipv6", ipv6_check, args)
    if command == "dhcp":
        return run_single("dhcp", dhcp_check, args)
    if command == "loop":
        return run_single("loop", loop_check, args)
    if command == "repair":
        return run_single("repair", repair_command, args)
    raise SystemExit(f"Unknown command: {command}")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    commands = {"scan", "connectivity", "dns", "nat", "ipv6", "dhcp", "loop", "repair", "port", "portping"}
    if not argv:
        argv = ["scan"] + argv
    elif argv[0].startswith("-") and argv[0] not in {"-h", "--help"}:
        argv = ["scan"] + argv
    parser = build_parser()
    args = parser.parse_args(argv)
    return dispatch(args)


if __name__ == "__main__":
    raise SystemExit(main())
