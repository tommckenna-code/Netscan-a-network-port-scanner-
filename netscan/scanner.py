"""NetScan - multithreaded TCP port scanner.

Usage:
    python3 scanner.py                      # prompts for a target
    python3 scanner.py 192.168.1.1          # scan ports 1-1024
    python3 scanner.py 192.168.1.1 -p 1-65535 -t 200
    python3 scanner.py 192.168.1.1 -o report.json

Only scan networks and devices you own or have written permission to test.
"""
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common ports: (service name, risk note or None)
SERVICES = {
    21:   ("FTP",       "cleartext credentials, often exploited"),
    22:   ("SSH",       None),
    23:   ("Telnet",    "unencrypted remote access"),
    25:   ("SMTP",      None),
    53:   ("DNS",       None),
    80:   ("HTTP",      "unencrypted web traffic"),
    110:  ("POP3",      "unencrypted email"),
    139:  ("NetBIOS",   "legacy Windows file sharing"),
    143:  ("IMAP",      "unencrypted email"),
    443:  ("HTTPS",     None),
    445:  ("SMB",       "frequent ransomware / worm target"),
    3306: ("MySQL",     "database exposed to network"),
    3389: ("RDP",       "remote desktop, heavily attacked"),
    5900: ("VNC",       "remote desktop, often weak auth"),
    8080: ("HTTP-Alt",  "alternative web server"),
    8443: ("HTTPS-Alt", None),
}

# Ports where the server speaks first, so a banner can be read passively.
# Others get a minimal HTTP probe.
HTTP_PORTS = {80, 8080, 8000, 8443, 443}


def parse_ports(spec):
    """'1-1024' -> (1, 1024); '80' -> (80, 80)."""
    try:
        if "-" in spec:
            lo, hi = (int(x) for x in spec.split("-", 1))
        else:
            lo = hi = int(spec)
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad port range: {spec!r}")
    if not (1 <= lo <= hi <= 65535):
        raise argparse.ArgumentTypeError("ports must satisfy 1 <= low <= high <= 65535")
    return lo, hi


def resolve(target):
    """Resolve hostname/IP to an IPv4 address, or exit with a clear message."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(f"  Error: cannot resolve '{target}'")


def grab_banner(host, port, timeout):
    """Best-effort service banner. Returns a short string or ''."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(128)
        text = data.decode(errors="ignore").strip().splitlines()
        return text[0][:60] if text else ""
    except OSError:
        return ""


def check_port(host, port, timeout):
    """Return (port, banner) if open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
    return port, grab_banner(host, port, timeout)


def service_for(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return (socket.getservbyport(port, "tcp").upper(), None)
    except OSError:
        return ("unknown", None)


def run_scan(host, low, high, timeout, threads):
    ip = resolve(host)
    started = datetime.now()
    t0 = time.perf_counter()

    print("=" * 62)
    print("  NetScan - TCP Port Scanner")
    print(f"  Target  : {host} ({ip})")
    print(f"  Ports   : {low}-{high}   Threads: {threads}   Timeout: {timeout}s")
    print(f"  Started : {started:%Y-%m-%d %H:%M:%S}")
    print("=" * 62)

    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check_port, ip, p, timeout) for p in range(low, high + 1)]
        for f in as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)

    open_ports.sort()
    elapsed = time.perf_counter() - t0

    results = []
    for port, banner in open_ports:
        name, risk = service_for(port)
        flag = "  [!] " + risk if risk else ""
        print(f"  {port:<6} OPEN  {name:<10}{flag}")
        if banner:
            print(f"         banner: {banner}")
        results.append({"port": port, "service": name, "risk": risk, "banner": banner})

    risky = sum(1 for r in results if r["risk"])
    print("=" * 62)
    print(f"  {len(results)} open port(s), {risky} flagged. "
          f"Scanned {high - low + 1} ports in {elapsed:.2f}s")
    print("=" * 62)

    return {
        "target": host, "ip": ip, "started": started.isoformat(timespec="seconds"),
        "ports_scanned": [low, high], "duration_s": round(elapsed, 2), "open": results,
    }

def main():
    ap = argparse.ArgumentParser(description="Multithreaded TCP port scanner")
    ap.add_argument("target", nargs="?", help="IP address or hostname")
    ap.add_argument("-p", "--ports", type=parse_ports, default=(1, 1024),
                    help="port or range, e.g. 80 or 1-1024 (default 1-1024)")
    ap.add_argument("-t", "--threads", type=int, default=200, help="worker threads (default 200)")
    ap.add_argument("--timeout", type=float, default=0.2, help="per-port timeout in seconds")
    ap.add_argument("-o", "--output", help="write results to a JSON file")
    args = ap.parse_args()

    print("\n  !  Only scan networks and devices you own or have permission to test.\n")
    target = args.target or input("  Enter IP address or hostname to scan: ").strip()
    if not target:
        sys.exit("  No target given.")

    report = run_scan(target, *args.ports, args.timeout, args.threads)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"  Report saved to {args.output}")


if __name__ == "__main__":
    main()