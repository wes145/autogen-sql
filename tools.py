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

def run_curl_headers(url: str) -> str:
    try:
        returncode, stdout, stderr = run_subprocess_with_timeout(["curl", "-I", url], timeout=15)
        if returncode != 0:
            return f"[curl error] {stderr}"
        return stdout
    except subprocess.TimeoutExpired:
        return f"[curl error] Timed out after 15 seconds"
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