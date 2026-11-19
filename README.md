# Nginx2Root Scanner

Passive NGINX version and HTTP/2 checker for **CVE-2026-123007**. Give it a list of hosts and it checks whether HTTP/2 is available and whether the public `Server` header shows an NGINX version in the affected range. It prints results as each host finishes. Use `--report` if you also want an HTML report.

## Usage

Requires Python 3.9 or newer. No extra packages are needed.

Create a file such as `subdomains.txt`, with one host or URL per line:

```text
example.com
https://app.example.com
https://api.example.com:8443
```

Hosts without a scheme are checked over HTTPS. Blank lines and lines starting with `#` are ignored.

Scan the list:

```bash
python3 scanner.py subdomains.txt
```

Run with more workers:

```bash
python3 scanner.py subdomains.txt --workers 10
```

Set the connection timeout (default is 5 seconds):

```bash
python3 scanner.py subdomains.txt --timeout 10
```

Generate an HTML report:

```bash
python3 scanner.py subdomains.txt --report
```

This creates `nginx2root-report.html` in the current directory. To choose a different name:

```bash
python3 scanner.py subdomains.txt --report scan-report.html
```

If a host has a certificate problem, `--insecure` skips certificate verification. Only use it when you understand the risk.

## Results

- **`POTENTIALLY VULNERABLE`** - HTTP/2 was negotiated and the `Server` header exposed an NGINX version in the affected range. The result is a lead to investigate, not proof that the server is vulnerable.
- **`NOT VULNERABLE`** - The tested HTTPS endpoint did not negotiate HTTP/2, or the version shown in the header is outside the affected range.
- **`UNKNOWN`** - The scanner could not get enough information to make either assessment. This can happen when the version is hidden, a proxy is in front of NGINX, or the connection fails.

For a potentially vulnerable host, Nginx2Root prints the version it found, the HTTP/2 result, the response status, and the `Server` header. The HTML report includes the same details and a short note on what to verify next.

## About CVE-2026-123007

The NGINX advisory describes this issue as memory corruption in HTTP/2 flow control. The upstream advisory lists NGINX versions from **1.9.5 through 1.31.8** as affected. The fixed upstream releases are **1.30.7** on the stable branch and **1.31.9** on the mainline branch.

A public version header does not always show what is running behind a proxy, and Linux vendors may backport fixes without changing the displayed version. Check the actual installed package and the vendor's advisory before treating a finding as confirmed.

- [NGINX security advisories](https://nginx.org/en/security_advisories.html)
- [NGINX 1.30.7 and 1.31.9 release notes](https://nginx.org/en/news.html)

## Disclaimer

Use this tool only on systems you own or have permission to test. It makes lightweight connection and HTTP requests; it does not send exploit payloads or try to crash the service.

The results are based on information visible from the tested endpoint. They are not a substitute for checking the server package and patch status.

## Author

Developed by [ChrishSec](https://github.com/ChrishSec).

Feel free to fork, modify, or contribute.

Contact: [Telegram](https://t.me/ChrishSec)
