#!/usr/bin/env python3

import argparse
import html
import http.client
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

BANNER = r"""
+======================================================================+
|                                                                      |
|   N G I N X 2 R O O T                                                |
|                                                                      |
|                     CVE-2026-123007 SCANNER                          |
|                                                                      |
|                     Developed by ChrishSec                           |
|                  https://github.com/ChrishSec                        |
|                                                                      |
|                 HTTP/2 exposure and version check                    |
|                      DETECTION ONLY                                  |
|                                                                      |
+======================================================================+
"""

VERSION_RE = re.compile(r"\bnginx\s*/\s*(\d+)\.(\d+)\.(\d+)\b", re.I)
AFFECTED_RANGES = "1.9.5-1.30.6 and 1.31.0-1.31.8"
FIXED_RELEASES = "1.30.7 (stable) or 1.31.9 (mainline), or a vendor-patched package"


def parse_target(line):
    value = line.strip()
    if not value or value.startswith("#"):
        return None
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError("expected a hostname or http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return {"target": value, "host": parsed.hostname, "port": port, "scheme": scheme}


def load_targets(path):
    targets = []
    seen = set()
    with open(path, "r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                item = parse_target(line)
            except ValueError as exc:
                print(f"[SKIP] line {line_no}: {exc}", file=sys.stderr)
                continue
            if item is None:
                continue
            key = (item["scheme"], item["host"].lower(), item["port"])
            if key not in seen:
                seen.add(key)
                targets.append(item)
    return targets


def make_ssl_context(insecure, alpn):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn)
    return ctx


def negotiate_http2(host, port, timeout, insecure):
    ctx = make_ssl_context(insecure, ["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.settimeout(timeout)
            return tls.selected_alpn_protocol() == "h2"


def get_server_header(target, timeout, insecure):
    conn = None
    try:
        if target["scheme"] == "https":
            ctx = make_ssl_context(insecure, ["http/1.1"])
            conn = http.client.HTTPSConnection(
                target["host"], target["port"], timeout=timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(
                target["host"], target["port"], timeout=timeout
            )
        conn.request("HEAD", "/", headers={"User-Agent": "Nginx2Root/1.0"})
        response = conn.getresponse()
        status = response.status
        server = response.getheader("Server", "") or ""
        if status in (405, 501):
            conn.close()
            if target["scheme"] == "https":
                ctx = make_ssl_context(insecure, ["http/1.1"])
                conn = http.client.HTTPSConnection(
                    target["host"], target["port"], timeout=timeout, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    target["host"], target["port"], timeout=timeout
                )
            conn.request("GET", "/", headers={
                "User-Agent": "Nginx2Root/1.0",
                "Range": "bytes=0-0",
            })
            response = conn.getresponse()
            status = response.status
            server = response.getheader("Server", "") or ""
        return status, server
    finally:
        if conn is not None:
            conn.close()


def parse_nginx_version(server):
    match = VERSION_RE.search(server or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_affected_upstream(version):
    return (
        (1, 9, 5) <= version <= (1, 30, 6)
        or (1, 31, 0) <= version <= (1, 31, 8)
    )


def assess(target, timeout, insecure):
    result = {
        "target": target["target"],
        "verdict": "UNKNOWN",
        "http2": "not checked",
        "server": "",
        "nginx_version": "",
        "http_status": "",
        "reason": "insufficient evidence",
    }

    if target["scheme"] != "https":
        result["reason"] = "HTTPS/ALPN check required; cleartext HTTP/2 is not tested"
        return result

    try:
        h2 = negotiate_http2(target["host"], target["port"], timeout, insecure)
        result["http2"] = "yes" if h2 else "no"
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["reason"] = f"TLS check failed: {exc.__class__.__name__}"
        return result

    try:
        status, server = get_server_header(target, timeout, insecure)
        result["http_status"] = status
        result["server"] = server
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        if not h2:
            result["verdict"] = "NOT VULNERABLE"
            result["reason"] = "HTTP/2 was not negotiated on this HTTPS endpoint"
        else:
            result["reason"] = f"HTTP request failed: {exc.__class__.__name__}"
        return result

    version = parse_nginx_version(server)
    if version:
        result["nginx_version"] = ".".join(str(x) for x in version)

    if not h2:
        result["verdict"] = "NOT VULNERABLE"
        result["reason"] = "HTTP/2 was not negotiated on this HTTPS endpoint"
    elif version and is_affected_upstream(version):
        result["verdict"] = "POTENTIALLY VULNERABLE"
        result["reason"] = (
            "HTTP/2 was negotiated and the Server header reports an upstream "
            "NGINX version in the affected range"
        )
    elif version:
        result["verdict"] = "NOT VULNERABLE"
        result["reason"] = (
            "HTTP/2 enabled, but the reported upstream NGINX version is "
            "outside the affected ranges"
        )
    elif "nginx" in server.lower():
        result["reason"] = "NGINX detected, but its version is hidden"
    else:
        result["reason"] = "HTTP/2 enabled, but the NGINX backend/version cannot be confirmed"

    return result


def print_result(row):
    """Print one finding; expand potentially vulnerable results with evidence."""
    print(f"[{row['verdict']}] {row['target']}", flush=True)

    if row.get("verdict") != "POTENTIALLY VULNERABLE":
        return

    details = [
        f"    HTTP/2: {row.get('http2', 'unknown')} (TLS ALPN)",
        f"    Server header: {row.get('server') or 'not disclosed'}",
        f"    Detected NGINX version: {row.get('nginx_version') or 'not identified'}",
        f"    HTTP response: {row.get('http_status') or 'unknown'}",
        f"    Affected upstream ranges: {AFFECTED_RANGES}",
        "    Evidence: HTTP/2 was negotiated and the exposed version falls in an affected range.",
        "    Confidence: Indicative only; a banner cannot confirm the actual backend build or vendor backports.",
        f"    Next step: Verify the installed package/build and vendor advisory; use {FIXED_RELEASES}.",
    ]
    for detail in details:
        print(detail, flush=True)


def build_html_report(results, output_path):
    """Write a standalone HTML report containing all scan results."""
    counts = {
        "POTENTIALLY VULNERABLE": 0,
        "NOT VULNERABLE": 0,
        "UNKNOWN": 0,
    }
    for row in results:
        counts[row.get("verdict", "UNKNOWN")] = counts.get(row.get("verdict", "UNKNOWN"), 0) + 1

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows_html = []
    for row in results:
        verdict = row.get("verdict", "UNKNOWN")
        css_class = {
            "POTENTIALLY VULNERABLE": "potential",
            "NOT VULNERABLE": "not-vulnerable",
            "UNKNOWN": "unknown",
        }.get(verdict, "unknown")
        target = html.escape(str(row.get("target", "")))
        server = html.escape(str(row.get("server") or "Not disclosed"))
        version = html.escape(str(row.get("nginx_version") or "Not identified"))
        http2 = html.escape(str(row.get("http2", "unknown")))
        status = html.escape(str(row.get("http_status") or "Unknown"))
        reason = html.escape(str(row.get("reason", "")))

        evidence_html = ""
        if verdict == "POTENTIALLY VULNERABLE":
            evidence_html = f"""
            <details class=\"evidence\" open>
              <summary>Detection evidence and recommended action</summary>
              <ul>
                <li>HTTP/2 was negotiated through TLS ALPN.</li>
                <li>The exposed NGINX version ({version}) is within the upstream affected ranges: {html.escape(AFFECTED_RANGES)}.</li>
                <li>The public Server header is not proof of the origin backend build; proxies and vendor backports may affect the result.</li>
                <li>Verify the installed package/build and vendor advisory. Remediate with {html.escape(FIXED_RELEASES)}.</li>
              </ul>
            </details>"""

        rows_html.append(f"""
        <tr class=\"{css_class}\">
          <td class=\"target\">{target}</td>
          <td><span class=\"verdict {css_class}\">{html.escape(verdict)}</span></td>
          <td>{http2}</td>
          <td>{version}</td>
          <td>{status}</td>
          <td>{server}</td>
          <td>{reason}{evidence_html}</td>
        </tr>""")

    document = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Nginx2Root - CVE-2026-123007 Report</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1020; --panel:#131b2e; --line:#26334d; --text:#e8edf7; --muted:#9ba9c2; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:32px; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }}
main {{ max-width:1500px; margin:0 auto; }}
header, .stat, .report-wrap {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; }}
header {{ padding:24px; margin-bottom:18px; }}
h1 {{ margin:0 0 6px; font-size:26px; letter-spacing:.04em; }}
.subtitle, .muted {{ color:var(--muted); }}
.stats {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-bottom:18px; }}
.stat {{ padding:16px; }}
.stat strong {{ display:block; font-size:25px; }}
.stat span {{ color:var(--muted); }}
.report-wrap {{ overflow:hidden; }}
.table-scroll {{ overflow-x:auto; }}
table {{ width:100%; border-collapse:collapse; min-width:1050px; }}
th, td {{ text-align:left; vertical-align:top; padding:13px 12px; border-bottom:1px solid var(--line); overflow-wrap:anywhere; }}
th {{ background:#18233a; color:#b8c5dc; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
tr:last-child td {{ border-bottom:0; }}
.target {{ min-width:190px; font-weight:600; }}
.verdict {{ display:inline-block; padding:4px 8px; border-radius:6px; font-size:11px; font-weight:700; white-space:nowrap; }}
.verdict.potential {{ background:#4a2d18; color:#ffca8a; }}
.verdict.not-vulnerable {{ background:#173b31; color:#9ce4c4; }}
.verdict.unknown {{ background:#3a344c; color:#d4c5ff; }}
.evidence {{ margin-top:8px; color:var(--muted); }}
.evidence summary {{ cursor:pointer; color:#ffca8a; font-weight:600; }}
.evidence ul {{ margin:8px 0 0; padding-left:20px; }}
footer {{ margin:18px 2px 0; color:var(--muted); font-size:12px; }}
@media(max-width:700px) {{ body {{ padding:14px; }} .stats {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} h1 {{ font-size:21px; }} }}
</style>
</head>
<body>
<main>
  <header>
    <h1>NGINX2ROOT</h1>
    <div class=\"subtitle\">CVE-2026-123007 scan report</div>
    <div class=\"muted\">Generated: {html.escape(generated)} · Targets scanned: {len(results)}</div>
  </header>
  <section class=\"stats\">
    <div class=\"stat\"><strong>{len(results)}</strong><span>Total targets</span></div>
    <div class=\"stat\"><strong>{counts['POTENTIALLY VULNERABLE']}</strong><span>Potentially vulnerable</span></div>
    <div class=\"stat\"><strong>{counts['NOT VULNERABLE']}</strong><span>Not vulnerable</span></div>
    <div class=\"stat\"><strong>{counts['UNKNOWN']}</strong><span>Unknown</span></div>
  </section>
  <section class=\"report-wrap\">
    <div class=\"table-scroll\">
      <table>
        <thead><tr><th>Target</th><th>Verdict</th><th>HTTP/2</th><th>NGINX version</th><th>HTTP status</th><th>Server header</th><th>Assessment</th></tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
      </table>
    </div>
  </section>
  <footer>Detection-only assessment. A remote Server header and TLS ALPN result cannot confirm the origin package build or vendor backported patches. Verify findings against the system package and vendor security advisory.</footer>
</main>
</body>
</html>
"""

    path = Path(output_path)
    path.write_text(document, encoding="utf-8")
    return path


def main():
    print(BANNER, flush=True)
    print()
    parser = argparse.ArgumentParser(prog="Nginx2Root")
    parser.add_argument("targets", help="Text file: one hostname or HTTP(S) URL per line")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent checks (default: 5, max: 20)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout per connection in seconds")
    parser.add_argument("--insecure", action="store_true", help="Ignore invalid TLS certificates")
    parser.add_argument(
        "--report",
        nargs="?",
        const="nginx2root-report.html",
        metavar="FILE",
        help="Generate an HTML report (default: nginx2root-report.html)",
    )
    args = parser.parse_args()

    if not 1 <= args.workers <= 20:
        parser.error("--workers must be between 1 and 20")
    if not 0.5 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.5 and 30")
    try:
        targets = load_targets(args.targets)
    except OSError as exc:
        parser.error(str(exc))
    if not targets:
        parser.error("no valid targets found")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(assess, item, args.timeout, args.insecure): item
            for item in targets
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                row = future.result()
            except Exception as exc:
                row = {
                    "target": item["target"],
                    "verdict": "UNKNOWN",
                    "http2": "not checked",
                    "server": "",
                    "nginx_version": "",
                    "http_status": "",
                    "reason": f"scanner error: {exc.__class__.__name__}",
                }
            results.append(row)
            print_result(row)

    if args.report:
        try:
            report_path = build_html_report(results, args.report)
        except OSError as exc:
            print(f"[ERROR] Could not write HTML report: {exc}", file=sys.stderr)
            return 1
        print(f"[REPORT] HTML report generated: {report_path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
