# To scan, open the terminal and run: python3 scanner.py 
# and enter the IP address of the device you want scanned.
import socket
from datetime import datetime

# Common ports and what service usually runs on them
SERVICES = {
    21:   "FTP          (risky — often exploited)",
    22:   "SSH          (secure remote access)",
    23:   "Telnet       (risky — unencrypted)",
    25:   "SMTP         (email sending)",
    53:   "DNS          (domain name lookup)",
    80:   "HTTP         (web server — unencrypted)",
    110:  "POP3         (email receiving)",
    143:  "IMAP         (email receiving)",
    443:  "HTTPS        (web server — encrypted)",
    3306: "MySQL        (database)",
    3389: "RDP          (remote desktop — often attacked)",
    8080: "HTTP-Alt     (alternative web server)",
    8443: "HTTPS-Alt    (alternative secure web)",
}

def check_port(host, port, timeout=0.5):
    """Try to connect to a port. Returns True if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def run_scan(host):
    print("=" * 55)
    print(f"  NetScan — Network Port Scanner")
    print(f"  Target : {host}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)
    print(f"  Scanning ports 1–1024... please wait\n")

    open_ports = []

    for port in range(1, 1025):
        if check_port(host, port):
            service = SERVICES.get(port, "Unknown service")
            print(f"  Port {port:<6} OPEN   {service}")
            open_ports.append(port)

    print("\n" + "=" * 55)
    if open_ports:
        print(f"  Scan complete. {len(open_ports)} open port(s) found.")
    else:
        print("  Scan complete. No open ports found.")
    print("=" * 55)

# --- Run the program ---
if __name__ == "__main__":
    print("\n  !  Only scan networks and devices you own. ! \n")
    target = input("  Enter IP address to scan: ").strip()
    run_scan(target)