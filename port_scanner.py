#!/usr/bin/env python3
"""
High-Speed Multi-Threaded Port Scanner
Fast, lightweight, zero-dependency port scanner and port availability checker.
Supports scanning localhost, LAN hosts, or remote targets with service detection and banner grabbing.
"""

import sys
import time
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports and their typical services
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    2049: "NFS",
    3000: "Dev-Web (Node/React)",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5000: "Dev-Web (Flask/UPnP)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt (Python/Django)",
    8080: "HTTP-Proxy / Dev-Server",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter / HTTP-Alt",
    9000: "SonarQube / Portainer",
    9090: "Prometheus / Cockpit",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# ANSI colors for terminal output
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"
COLOR_RESET = "\033[0m"


def get_banner(target_ip, port, timeout=1.0):
    """Attempt to grab service banner or HTTP header."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, port))

        # Send HTTP probe for common web ports
        if port in (80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888):
            probe = f"HEAD / HTTP/1.0\r\nHost: {target_ip}\r\nUser-Agent: PortScanner/1.0\r\n\r\n".encode("latin1")
            s.sendall(probe)
        else:
            # Generic probe (CRLF) to trigger banner
            s.sendall(b"\r\n")

        data = s.recv(1024)
        s.close()
        if data:
            # Extract first non-empty line
            lines = data.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                line = line.strip()
                if line:
                    return line[:60]
    except Exception:
        pass
    return None


def scan_port(target_ip, port, timeout=0.8, grab_banner=False):
    """Scan a single TCP port and return result dict if open, else None."""
    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target_ip, port))
        latency = (time.time() - start_time) * 1000  # ms
        if result == 0:
            service = COMMON_PORTS.get(port, "")
            if not service:
                try:
                    service = socket.getservbyport(port, "tcp")
                except Exception:
                    service = "unknown"

            banner = None
            if grab_banner:
                banner = get_banner(target_ip, port, timeout=min(timeout, 1.2))

            return {
                "port": port,
                "state": "OPEN",
                "service": service,
                "latency_ms": round(latency, 2),
                "banner": banner
            }
    except Exception:
        pass
    finally:
        s.close()
    return None


def parse_port_range(port_spec):
    """Parse port specification like '80,443', '1-1024', or combination."""
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_p = max(1, int(start.strip()))
                end_p = min(65535, int(end.strip()))
                if start_p <= end_p:
                    ports.update(range(start_p, end_p + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(list(ports))


def check_port_availability(port, host="127.0.0.1"):
    """Quick check if a local port is free to bind or currently in use."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        # Check if already listening
        res = s.connect_ex((host, port))
        s.close()
        if res == 0:
            print(f"{COLOR_RED}✗ Port {port} is OCCUPIED (In Use){COLOR_RESET}")
            service = COMMON_PORTS.get(port, "unknown")
            print(f"  Service suggestion: {service}")
            return False
        else:
            print(f"{COLOR_GREEN}✓ Port {port} is AVAILABLE (Free){COLOR_RESET}")
            return True
    except Exception as e:
        print(f"Error checking port: {e}")
        return False


def run_scanner():
    parser = argparse.ArgumentParser(
        description="Fast Multi-Threaded TCP Port Scanner & Port Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Scan top common ports on localhost:
  python3 port_scanner.py

  # Scan a specific IP on your LAN:
  python3 port_scanner.py 192.168.1.100

  # Scan custom port range (e.g. 8000 to 8100):
  python3 port_scanner.py --range 8000-8100

  # Scan specific ports with service banner grabbing:
  python3 port_scanner.py -p 80,443,8080,3306 --banner

  # Quickly check if a single port is free to use:
  python3 port_scanner.py --check 8080
        """
    )

    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target host/IP (default: 127.0.0.1)")
    parser.add_argument("--check", "-c", type=int, metavar="PORT", help="Quick check if a single port is free or occupied")
    parser.add_argument("--ports", "-p", type=str, help="Comma-separated ports to scan (e.g. '80,443,8080')")
    parser.add_argument("--range", "-r", type=str, help="Port range to scan (e.g. '1-1024' or '8000-9000')")
    parser.add_argument("--all", "-a", action="store_true", help="Scan all 65535 ports (takes longer)")
    parser.add_argument("--threads", "-t", type=int, default=100, help="Number of concurrent worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.8, help="Connection timeout in seconds (default: 0.8)")
    parser.add_argument("--banner", "-b", action="store_true", help="Grab service banner or HTTP header")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # Mode 1: Quick single port check
    if args.check:
        check_port_availability(args.check, args.target)
        sys.exit(0)

    # Resolve target hostname
    target = args.target.strip()
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"{COLOR_RED}Error: Cannot resolve hostname '{target}': {e}{COLOR_RESET}")
        sys.exit(1)

    # Determine port list
    if args.ports:
        ports = parse_port_range(args.ports)
    elif args.range:
        ports = parse_port_range(args.range)
    elif args.all:
        ports = list(range(1, 65536))
    else:
        # Default: common ports + standard web/dev ports
        ports = sorted(list(COMMON_PORTS.keys()))

    if not ports:
        print(f"{COLOR_RED}Error: No valid ports specified.{COLOR_RESET}")
        sys.exit(1)

    if not args.json:
        border = "═" * 65
        print(f"{COLOR_CYAN}{border}{COLOR_RESET}")
        print(f" {COLOR_BOLD}🔍 SCANNING TARGET:{COLOR_RESET} {target} ({target_ip})")
        print(f" {COLOR_BOLD}🔢 PORTS TO SCAN:{COLOR_RESET}  {len(ports)} ports")
        print(f" {COLOR_BOLD}⚡ THREADS:{COLOR_RESET}        {args.threads} threads (Timeout: {args.timeout}s)")
        print(f"{COLOR_CYAN}{border}{COLOR_RESET}")
        print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<22} {'LATENCY':<10}")
        print("─" * 65)

    open_ports = []
    start_time = time.time()

    # Run multi-threaded scan
    with ThreadPoolExecutor(max_workers=min(args.threads, len(ports))) as executor:
        futures = {
            executor.submit(scan_port, target_ip, p, args.timeout, args.banner): p
            for p in ports
        }

        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                if not args.json:
                    port_str = f"{res['port']}/tcp"
                    state_str = f"{COLOR_GREEN}{res['state']}{COLOR_RESET}"
                    service_str = res['service']
                    latency_str = f"{res['latency_ms']} ms"
                    print(f"{port_str:<10} {state_str:<19} {service_str:<22} {latency_str:<10}")
                    if res.get("banner"):
                        print(f"  └─ {COLOR_DIM}Banner: {res['banner']}{COLOR_RESET}")

    total_time = time.time() - start_time
    open_ports.sort(key=lambda x: x["port"])

    if args.json:
        import json
        print(json.dumps({
            "target": target,
            "ip": target_ip,
            "scanned_ports_count": len(ports),
            "open_ports_count": len(open_ports),
            "elapsed_seconds": round(total_time, 2),
            "open_ports": open_ports
        }, indent=2))
    else:
        print("─" * 65)
        print(f"Finished in {total_time:.2f} seconds.")
        if open_ports:
            print(f"{COLOR_BOLD}{COLOR_GREEN}✓ Found {len(open_ports)} open port(s).{COLOR_RESET}\n")
        else:
            print(f"{COLOR_YELLOW}No open ports found in the scanned range.{COLOR_RESET}\n")


if __name__ == "__main__":
    run_scanner()
