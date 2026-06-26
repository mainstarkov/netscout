#!/usr/bin/env python3
"""NetScout — Domain & IP reconnaissance CLI tool."""

import argparse
import json
import math
import socket
import ssl
import urllib.request
from datetime import datetime, timezone


# ── Terminal colors ──────────────────────────────────────────────────

class C:
    GRAY    = "\033[90m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ULINE   = "\033[4m"
    RESET   = "\033[0m"


BOX_WIDTH = 60


# ── Banner ───────────────────────────────────────────────────────────

BANNER = f"""
{C.CYAN}{C.BOLD}  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝{C.RESET}
{C.GRAY}  {'─' * BOX_WIDTH}{C.RESET}
{C.DIM}  Domain & IP Recon Tool v2.1                   {C.GRAY}by mainstarkov{C.RESET}
{C.GRAY}  {'─' * BOX_WIDTH}{C.RESET}
"""


# ── Box-drawing UI ───────────────────────────────────────────────────

def box_top(title: str, icon: str, color: str):
    w = BOX_WIDTH - 2
    print(f"\n{color}  {icon} ╔{'═' * w}╗{C.RESET}")
    pad = max(0, w - 3 - len(title))
    print(f"{color}    ║  {C.BOLD}{title}{C.RESET}{color}{' ' * pad}║{C.RESET}")
    print(f"{color}    ╠{'═' * w}╣{C.RESET}")


def box_row(label: str, value: str, color: str, val_color: str = ""):
    vc = val_color or C.WHITE
    padded = f"{label:<14}"
    vlen = len(value)
    pad = max(0, BOX_WIDTH - 3 - 14 - 3 - vlen)
    print(f"{color}    ║  {C.YELLOW}{padded}{C.RESET} {vc}{value}{C.RESET}{' ' * pad}{color}║{C.RESET}")


def box_sep(color: str):
    print(f"{color}    ╟{'─' * (BOX_WIDTH - 2)}╢{C.RESET}")


def box_end(color: str):
    print(f"{color}    ╚{'═' * (BOX_WIDTH - 2)}╝{C.RESET}")


def dot(ok: bool) -> str:
    return f"{C.GREEN}●{C.RESET}" if ok else f"{C.RED}●{C.RESET}"


def flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))


# ── Network helpers ──────────────────────────────────────────────────

def fetch_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetScout/2.1"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def resolve_domain(domain: str) -> list[str]:
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    try:
        return list(dict.fromkeys(r[4][0] for r in socket.getaddrinfo(domain, None)))
    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> list[str]:
    try:
        result = socket.gethostbyaddr(ip)
        names = [result[0]] + list(result[1])
        return [n for n in dict.fromkeys(names) if not n.endswith(".in-addr.arpa")]
    except socket.herror:
        return []


def scan_ports(ip: str, ports: dict[int, str]) -> dict[int, bool]:
    results = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            results[port] = sock.connect_ex((ip, port)) == 0
        except OSError:
            results[port] = False
        finally:
            sock.close()
    return results


def ssl_info(domain: str) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "issuer":  dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?"),
                "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName", "?"),
                "expires": cert.get("notAfter", "?"),
                "serial":  cert.get("serialNumber", "")[:20],
            }
    except Exception:
        return None


def http_info(domain: str) -> dict | None:
    for proto in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{proto}://{domain}", headers={"User-Agent": "NetScout/2.1"}, method="HEAD"
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return {
                    "status":  r.status,
                    "server":  r.headers.get("Server", "—"),
                    "powered": r.headers.get("X-Powered-By", "—"),
                    "proto":   proto.upper(),
                }
        except Exception:
            continue
    return None


# ── Multi-source geolocation ────────────────────────────────────────

GEO_FIELDS = ("source", "country", "cc", "region", "city", "district",
              "zip", "lat", "lon", "tz", "isp", "org", "asn", "proxy", "hosting")


def _geo_entry(**kw) -> dict:
    return {k: kw.get(k, "") for k in GEO_FIELDS}


def geo_ipapi(ip: str) -> dict | None:
    d = fetch_json(
        f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
        f"regionName,city,district,zip,lat,lon,timezone,isp,org,as,proxy,hosting"
    )
    if d and d.get("status") == "success":
        return _geo_entry(
            source="ip-api.com", country=d.get("country"), cc=d.get("countryCode"),
            region=d.get("regionName"), city=d.get("city"), district=d.get("district"),
            zip=d.get("zip"), lat=d.get("lat"), lon=d.get("lon"), tz=d.get("timezone"),
            isp=d.get("isp"), org=d.get("org"), asn=d.get("as"),
            proxy=d.get("proxy", False), hosting=d.get("hosting", False),
        )
    return None


def geo_ipwhois(ip: str) -> dict | None:
    d = fetch_json(f"http://ipwho.is/{ip}")
    if d and d.get("success"):
        conn = d.get("connection", {})
        tz = d.get("timezone", {})
        return _geo_entry(
            source="ipwho.is", country=d.get("country"), cc=d.get("country_code"),
            region=d.get("region"), city=d.get("city"), zip=d.get("postal"),
            lat=d.get("latitude"), lon=d.get("longitude"),
            tz=tz.get("id") if isinstance(tz, dict) else "",
            isp=conn.get("isp"), org=conn.get("org"),
            asn=f"AS{conn.get('asn', '')} {conn.get('org', '')}",
            proxy=d.get("security", {}).get("proxy", False),
            hosting=d.get("type") == "hosting",
        )
    return None


def geo_ipinfo(ip: str) -> dict | None:
    d = fetch_json(f"https://ipinfo.io/{ip}/json")
    if d and "bogon" not in d:
        parts = d.get("loc", ",").split(",")
        lat = float(parts[0]) if len(parts) == 2 and parts[0] else None
        lon = float(parts[1]) if len(parts) == 2 and parts[1] else None
        return _geo_entry(
            source="ipinfo.io", country=d.get("country"), cc=d.get("country"),
            region=d.get("region"), city=d.get("city"), zip=d.get("postal"),
            lat=lat, lon=lon, tz=d.get("timezone"),
            isp=d.get("org"), org=d.get("org"), asn=d.get("org"),
        )
    return None


def geolocate(ip: str) -> list[dict]:
    results = []
    for fn in (geo_ipapi, geo_ipwhois, geo_ipinfo):
        r = fn(ip)
        if r:
            results.append(r)
    return results


def avg_coords(geos: list[dict]) -> tuple[float, float] | None:
    lats = [g["lat"] for g in geos if g.get("lat") is not None]
    lons = [g["lon"] for g in geos if g.get("lon") is not None]
    if not lats:
        return None
    return round(sum(lats) / len(lats), 6), round(sum(lons) / len(lons), 6)


def spread_km(geos: list[dict]) -> float:
    lats = [g["lat"] for g in geos if g.get("lat") is not None]
    lons = [g["lon"] for g in geos if g.get("lon") is not None]
    if len(lats) < 2:
        return 0.0
    dlat = (max(lats) - min(lats)) * 111.0
    dlon = (max(lons) - min(lons)) * 111.0 * math.cos(math.radians(sum(lats) / len(lats)))
    return round(math.sqrt(dlat**2 + dlon**2), 1)


def maps_url(lat: float, lon: float) -> str:
    return f"https://www.google.com/maps?q={lat},{lon}"


# ── Scan target ──────────────────────────────────────────────────────

PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    5432: "Postgres", 8080: "Proxy", 8443: "Alt-HTTPS",
}


def scan_target(target: str, skip_ports: bool = False):
    is_ip = False
    try:
        socket.inet_aton(target)
        is_ip = True
    except OSError:
        pass

    domain = None
    ip = target if is_ip else None

    # DNS
    if not is_ip:
        domain = target.replace("https://", "").replace("http://", "").strip("/")
        box_top(f"DNS RESOLUTION — {domain}", "🔍", C.CYAN)
        ips = resolve_domain(domain)
        if not ips:
            box_row("Status", "✗ Could not resolve", C.CYAN, C.RED)
            box_end(C.CYAN)
            return
        v4 = [i for i in ips if ":" not in i]
        v6 = [i for i in ips if ":" in i]
        for addr in v4:
            box_row("IPv4", addr, C.CYAN, C.GREEN)
        for addr in v6:
            box_row("IPv6", addr, C.CYAN, C.BLUE)
        box_row("Records", f"{len(ips)} total ({len(v4)} A / {len(v6)} AAAA)", C.CYAN)
        box_end(C.CYAN)
        ip = v4[0] if v4 else ips[0]

    # Reverse DNS
    box_top(f"REVERSE DNS — {ip}", "🔄", C.MAGENTA)
    hostnames = reverse_dns(ip)
    if hostnames:
        for h in hostnames:
            box_row("Hostname", h, C.MAGENTA, C.GREEN)
    else:
        box_row("Result", "No PTR records found", C.MAGENTA, C.GRAY)
    box_end(C.MAGENTA)

    # Geolocation
    geos = geolocate(ip)
    box_top(f"GEOLOCATION — {ip}  [{len(geos)} sources]", "🌍", C.GREEN)

    if geos:
        g = geos[0]
        box_row("Country", f"{flag(g['cc'])}  {g['country']} ({g['cc']})", C.GREEN)
        box_row("Region", g.get("region") or "—", C.GREEN)
        box_row("City", g.get("city") or "—", C.GREEN)
        if g.get("district"):
            box_row("District", g["district"], C.GREEN)
        if g.get("zip"):
            box_row("ZIP / Postal", g["zip"], C.GREEN)
        box_row("Timezone", g.get("tz") or "—", C.GREEN)
        box_sep(C.GREEN)
        box_row("ISP", g.get("isp") or "—", C.GREEN)
        box_row("Organization", g.get("org") or "—", C.GREEN)
        box_row("AS Number", g.get("asn") or "—", C.GREEN)
        box_sep(C.GREEN)

        is_proxy = any(x.get("proxy") for x in geos)
        is_dc = any(x.get("hosting") for x in geos)
        box_row("Proxy / VPN", f"{dot(not is_proxy)} {'Yes' if is_proxy else 'No'}", C.GREEN)
        box_row("Hosting / DC", f"{dot(not is_dc)} {'Yes' if is_dc else 'No'}", C.GREEN)
        box_sep(C.GREEN)

        coords = avg_coords(geos)
        if coords:
            box_row("Avg Coords", f"{coords[0]}, {coords[1]}", C.GREEN)
            sp = spread_km(geos)
            if sp > 0:
                sc = C.GREEN if sp < 50 else (C.YELLOW if sp < 200 else C.RED)
                box_row("Spread", f"{sc}{sp} km{C.RESET}", C.GREEN)
            box_row("📍 Map", f"{C.ULINE}{C.CYAN}{maps_url(*coords)}{C.RESET}", C.GREEN)

        box_sep(C.GREEN)
        for src in geos:
            lat, lon = src.get("lat", "?"), src.get("lon", "?")
            box_row(f"⊕ {src['source']}", f"{src['city']}, {src['region']}  ({lat}, {lon})", C.GREEN, C.GRAY)
    else:
        box_row("Status", "✗ Geolocation unavailable", C.GREEN, C.RED)

    box_end(C.GREEN)

    # Port scan
    ports = {} if skip_ports else PORTS
    if ports:
        box_top(f"PORT SCAN — {ip}", "🔌", C.YELLOW)
        results = scan_ports(ip, ports)
        opened = [p for p, ok in results.items() if ok]
        closed = [p for p, ok in results.items() if not ok]
        for p in opened:
            box_row(f":{p}", f"{C.GREEN}● OPEN{C.RESET}    {ports[p]}", C.YELLOW)
        if closed:
            s = ", ".join(str(p) for p in closed[:6])
            if len(closed) > 6:
                s += f" +{len(closed) - 6} more"
            box_row("Closed", f"{C.GRAY}{s}{C.RESET}", C.YELLOW)
        box_row("Summary", f"{len(opened)} open / {len(closed)} closed", C.YELLOW)
        box_end(C.YELLOW)

    # SSL
    if domain:
        box_top(f"SSL CERTIFICATE — {domain}", "🔒", C.BLUE)
        si = ssl_info(domain)
        if si:
            box_row("Subject", si["subject"], C.BLUE, C.GREEN)
            box_row("Issuer", si["issuer"], C.BLUE)
            box_row("Expires", si["expires"], C.BLUE)
            box_row("Serial", si["serial"] + "...", C.BLUE, C.GRAY)
        else:
            box_row("Status", "No SSL / connection failed", C.BLUE, C.RED)
        box_end(C.BLUE)

    # HTTP
    if domain:
        box_top(f"HTTP INFO — {domain}", "📡", C.CYAN)
        hi = http_info(domain)
        if hi:
            sc = C.GREEN if hi["status"] < 400 else C.RED
            box_row("Status", f"{sc}{hi['status']}{C.RESET}", C.CYAN)
            box_row("Protocol", hi["proto"], C.CYAN)
            box_row("Server", hi["server"], C.CYAN)
            box_row("Powered By", hi["powered"], C.CYAN)
        else:
            box_row("Status", "Not reachable via HTTP(S)", C.CYAN, C.RED)
        box_end(C.CYAN)

    # Footer
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{C.GRAY}  {'─' * BOX_WIDTH}{C.RESET}")
    print(f"{C.DIM}  Scan completed at {ts}{C.RESET}")
    print(f"{C.GRAY}  {'─' * BOX_WIDTH}{C.RESET}\n")


# ── JSON output ──────────────────────────────────────────────────────

def scan_json(targets: list[str], skip_ports: bool = False) -> list[dict]:
    results = []
    for target in targets:
        entry = {"target": target, "timestamp": datetime.now(timezone.utc).isoformat()}

        try:
            socket.inet_aton(target)
            is_ip = True
        except OSError:
            is_ip = False

        if is_ip:
            entry["ip"] = target
            entry["domains"] = reverse_dns(target)
        else:
            ips = resolve_domain(target)
            entry["ips"] = ips
            if ips:
                entry["domains"] = reverse_dns(ips[0])
                entry["ip"] = ips[0]

        ip = entry.get("ip")
        if ip:
            geos = geolocate(ip)
            if geos:
                entry["geo_sources"] = geos
                coords = avg_coords(geos)
                if coords:
                    entry["avg_coords"] = {"lat": coords[0], "lon": coords[1]}
                    entry["spread_km"] = spread_km(geos)
                    entry["maps_url"] = maps_url(*coords)

            if not skip_ports:
                port_results = scan_ports(ip, PORTS)
                entry["ports"] = {
                    f"{p}/{PORTS[p]}": "open" if ok else "closed"
                    for p, ok in port_results.items()
                }

        if not is_ip:
            si = ssl_info(target)
            if si:
                entry["ssl"] = si

        results.append(entry)
    return results


# ── Entry point ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="netscout", description="Domain & IP recon tool")
    parser.add_argument("targets", nargs="+", help="domain(s) or IP(s) to scan")
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument("--no-ports", action="store_true", help="skip port scanning")
    args = parser.parse_args()

    print(BANNER)

    if args.json:
        print(json.dumps(scan_json(args.targets, args.no_ports), indent=2, ensure_ascii=False))
    else:
        for i, t in enumerate(args.targets):
            if i > 0:
                print(f"\n{C.CYAN}{'━' * (BOX_WIDTH + 4)}{C.RESET}")
            scan_target(t.strip(), args.no_ports)


if __name__ == "__main__":
    main()
