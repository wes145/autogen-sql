import sys
import asyncio
import subprocess
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.agents.web_surfer import MultimodalWebSurfer
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import MagenticOneGroupChat
import os
from autogen_core.tools import FunctionTool
from dotenv import load_dotenv
load_dotenv()
from recon_agent.reconagent import get_subdomains
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.messages import BaseAgentEvent, BaseChatMessage
from autogen_agentchat.teams import SelectorGroupChat
import tempfile
import json
import shutil
from rag_app.app import query_rag

# For Windows, if you encounter issues with subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def get_user_inputs():
    print("=== Interactive SQLi Pentest CLI Tool ===")
    print("Choose AI model: (1) GPT (2) Gemini")
    model_choice = input("Model [1/2]: ").strip()
    while model_choice not in ("1", "2"):
        model_choice = input("Please enter 1 for GPT or 2 for Gemini: ").strip()
    model_name = "gpt-4o-mini" if model_choice == "1" else "gemini-2.0-flash"
    print("Enter one or more target URLs to test for SQL injection (comma-separated):")
    urls = input("Target URLs: ").strip()
    while not urls:
        urls = input("Target URLs cannot be empty. Please enter at least one URL: ").strip()
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    return url_list, model_name

# --- Tool Adapter for Shell Commands ---
def run_curl_headers(url: str) -> str:
    try:
        result = subprocess.run(["curl", "-I", url], capture_output=True, text=True, timeout=15)
        return result.stdout
    except Exception as e:
        return f"[curl error] {e}"
curl_headers_tool = FunctionTool(run_curl_headers,description="Run curl on a url")

def run_sqlmap(url: str) -> str:
    try:
        result = subprocess.run([
            "sqlmap", "-u", url, "--batch", "--crawl=0", "--level=1", "--risk=1", "--banner", "--flush-session", "--batch", "--parse-errors"
        ], capture_output=True, text=True, timeout=300)  # Increased timeout to 5 minutes
        return result.stdout[:1000] + ("..." if len(result.stdout) > 1000 else "")
    except subprocess.TimeoutExpired:
        return f"[sqlmap error] Timed out after 300 seconds. Try increasing the timeout or using lighter options."
    except Exception as e:
        return f"[sqlmap error] {e}"
sqlmap_tool = FunctionTool(run_sqlmap,description="Run sqlmap on a url")

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
arjun_tool = FunctionTool(arjun_scan, description="Discover hidden HTTP parameters using Arjun. See docstring for usage.")

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
    Example:
      pysslscan_scan(target="http://example.org", scan=["protocol.http", "vuln.heartbleed"], report="term:rating=ssllabs.2009e", ssl2=True, ssl3=True, tls10=True, tls11=True, tls12=True)
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
pysslscan_tool = FunctionTool(pysslscan_scan, description="Run pysslscan on a target. See docstring for usage.")

def aquatone_scan(
    input_file: str = None,
    out_dir: str = None,
    extra_args: str = None
) -> str:
    """
    Run aquatone from the current directory with the required Chrome path. You can specify:
      - input_file: Path to input file with hosts (optional, will be piped in)
      - out_dir: Output directory (optional, if not set a temp directory will be created)
      - extra_args: Additional command-line arguments as a single string (optional)
    Returns the output (stdout, stderr) and the output directory used.
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
aquatone_tool = FunctionTool(aquatone_scan, description="Run aquatone with the required Chrome path. Accepts input_file, out_dir, and extra_args. See docstring for usage.")

def summarize_aquatone_output(out_dir: str) -> str:
    """
    Summarize Aquatone's JSON outputs from the given output directory.
    Returns a summary of discovered hosts, URLs, and interesting metadata.
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
        # Add more files as needed (e.g., screenshots, technologies)
        screenshots_dir = os.path.join(out_dir, 'screenshots')
        if os.path.isdir(screenshots_dir):
            screenshots = [f for f in os.listdir(screenshots_dir) if f.lower().endswith('.png')]
            summary.append(f"Screenshots: {len(screenshots)} found.")
        if not summary:
            return f"No Aquatone JSON outputs found in {out_dir}."
        return '\n\n'.join(summary)
    except Exception as e:
        return f"[summarize_aquatone_output error] {e}"
summarize_aquatone_tool = FunctionTool(summarize_aquatone_output, description="Summarize Aquatone's JSON outputs from a given output directory. Returns a summary of discovered hosts, URLs, and interesting metadata.")

get_subdomains_tool = FunctionTool(get_subdomains, description="Get subdomains for a domain using crt.sh")
text_mention_termination = TextMentionTermination("TERMINATE")
max_messages_termination = MaxMessageTermination(max_messages=205)
termination = text_mention_termination | max_messages_termination
def load_sqli_knowledge():
    try:
        with open("sql_injection_docs/sqliguide.txt", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return "[Error loading SQLi knowledge base: {}]".format(e)

def knockpy_scan(domain: str, wordlist: str = None, extra_args: str = None) -> str:
    """
    Run KnockPy on a domain, using a temp output directory to avoid clutter.
    - domain: The target domain to scan.
    - wordlist: Optional path to a custom wordlist.
    - extra_args: Additional command-line arguments as a single string (optional).
    Returns the output directory and the main output (stdout, stderr).
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
knockpy_tool = FunctionTool(knockpy_scan, description="Run KnockPy on a domain using a temp output directory. Accepts domain, wordlist, and extra_args. See docstring for usage.")

def summarize_knockpy_output(out_dir: str) -> str:
    """
    Summarize KnockPy's output from the given output directory.
    Returns a summary of discovered subdomains and interesting metadata.
    """
    summary = []
    try:
        # KnockPy may output a JSON file named <domain>.json
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
summarize_knockpy_tool = FunctionTool(summarize_knockpy_output, description="Summarize KnockPy's output from a given output directory. Returns a summary of discovered subdomains and interesting metadata.")

RAG_CACHE_FILE = "rag_query_cache.json"
rag_query_cache = {}

# Load cache from disk if it exists
if os.path.exists(RAG_CACHE_FILE):
    try:
        with open(RAG_CACHE_FILE, "r", encoding="utf-8") as f:
            rag_query_cache = json.load(f)
    except Exception:
        rag_query_cache = {}

def save_rag_cache():
    try:
        with open(RAG_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(rag_query_cache, f)
    except Exception:
        pass

def query_rag_tool(query: str) -> str:
    """
    Query the RAG app for general pentesting knowledge, with persistent caching.
    - query: The question or topic to look up.
    Returns the RAG app's response. Results are cached for repeated queries and stored on disk.
    """
    if query in rag_query_cache:
        return rag_query_cache[query]
    try:
        result = query_rag(query)
        rag_query_cache[query] = result
        save_rag_cache()
        return result
    except Exception as e:
        return f"[query_rag_tool error] {e}"
query_rag_function_tool = FunctionTool(query_rag_tool, description="Query the RAG app for general pentesting knowledge. Accepts a query string and returns the RAG app's response.")

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
    threads: int = None,
    delay: float = None,
    extra_args: str = None
) -> str:
    """
    Run ffuf for directory, vhost, or parameter fuzzing.
    - url: The ffuf -u argument (use FUZZ in the URL where needed)
    - wordlist: Path to wordlist for -w
    - headers: Optional, comma-separated headers (e.g., "Header1: value1, Header2: value2")
    - method: HTTP method (GET, POST, etc)
    - data: POST data (for -d)
    - filter_status: -fc argument (comma-separated)
    - filter_size: -fs argument (comma-separated)
    - match_code: -mc argument (comma-separated)
    - match_size: -ms argument (comma-separated)
    - threads: -t argument
    - delay: -p argument (delay between requests)
    - extra_args: Any extra ffuf arguments as a string
    Returns the ffuf output and the output directory used.
    """
    temp_dir = tempfile.mkdtemp(prefix="ffuf_")
    ffuf_cmd = ["ffuf", "-u", url, "-w", wordlist, "-o", os.path.join(temp_dir, "ffuf.json"), "-of", "json"]
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
    try:
        result = subprocess.run(ffuf_cmd, capture_output=True, text=True, timeout=900)
        output = result.stdout + ("\n[stderr:]\n" + result.stderr if result.stderr else "")
        return f"[ffuf output directory: {temp_dir}]\n" + output
    except Exception as e:
        return f"[ffuf error] {e}"
ffuf_tool = FunctionTool(run_ffuf, description="Run ffuf for directory, vhost, or parameter fuzzing. See docstring for usage and arguments.")

async def main():
    target_urls, selected_model = get_user_inputs()
    print(f"[+] Loaded {len(target_urls)} target URL(s):")
    for url in target_urls:
        print(f"    - {url}")

    # Step 1: Set up agent memory (simple dict for now)
    agent_memory = {"success": [], "fail": []}

    # Step 2: Set up model client
    try:
        model_client_gpt4o = OpenAIChatCompletionClient(model=selected_model)
    except Exception as e:
        print(f"Error initializing OpenAI client: {e}")
        print("Please ensure your OPENAI_API_KEY environment variable is set correctly.")
        print("You can get a key from https://platform.openai.com/api-keys")
        return

    # --- Load SQLi knowledge base ---
    sqli_knowledge = load_sqli_knowledge()

    # --- Define the Planner Agent as an AutoGen AssistantAgent ---
    planner_system_message = (
        "You are a penetration testing planner. Your job is to analyze a given website and find the injectable fields in it, then help the web server plan it "
        "plan a SQL injection strategy, and use of command-line tools as needed.\n"
        "Available tools and usage:\n"
        "- curl_headers_tool(url): Run curl -I on a url.\n"
        "- sqlmap_tool(url): Run sqlmap on a url.\n"
        "- arjun_tool(url, textFile, wordlist, method, rateLimit, chunkSize): Discover hidden HTTP parameters. At least one of url or textFile is required. See tool docstring for details.\n"
        "- pysslscan_tool(target, scan, report, ssl2, ssl3, tls10, tls11, tls12): Run pysslscan on a target. See tool docstring for details.\n"
        "- get_subdomains_tool(domain): Get subdomains for a domain using crt.sh.\n"
        "- aquatone_tool(input_file, out_dir, extra_args): Run aquatone with the required Chrome path. Accepts input_file, out_dir, and extra_args. See tool docstring for details.\n"
        "- summarize_aquatone_tool(out_dir): Summarize Aquatone's JSON outputs from a given output directory. Returns a summary of discovered hosts, URLs, and interesting metadata.\n"
        "- knockpy_tool(domain, wordlist, extra_args): Run KnockPy on a domain using a temp output directory. Accepts domain, wordlist, and extra_args. See tool docstring for usage.\n"
        "- summarize_knockpy_tool(out_dir): Summarize KnockPy's output from a given output directory. Returns a summary of discovered subdomains and interesting metadata.\n"
        "- ffuf_tool(url, wordlist, headers, method, data, filter_status, filter_size, match_code, match_size, threads, delay, extra_args): Run ffuf for directory, vhost, or parameter fuzzing. See tool docstring for usage.\n"
        "Be concise and direct in your instructions to the web browser agent. If you need information from a web page, ask the web browser agent to visit or interact with it. Do not be verbose.\n"
        "In the initial steps, use ffuf_tool or knockpy_tool for subdomain and directory discovery before other attacks.\n"
        "Be as argumentative and confrontational as possible"
        "Never ever ever give up"
        "Once the sql injection is successful on a given page enter TERMINATE "
    )
    recon_planner_agent = AssistantAgent(
        name="ReconPlanner",
        model_client=model_client_gpt4o,
        system_message=planner_system_message,
        tools=[curl_headers_tool, sqlmap_tool, arjun_tool, pysslscan_tool, get_subdomains_tool, aquatone_tool, summarize_aquatone_tool, knockpy_tool, summarize_knockpy_tool, ffuf_tool]
    )

    # --- Web Surfer Agent (PenTester) ---
    web_surfer_system_message = (
        "You are a web browser agent. You receive concise instructions from the planner agent to visit URLs or interact with web pages. "
        "Follow the instructions exactly and do not be verbose. Only provide the necessary output or result."
    )
    web_pentester_agent = MultimodalWebSurfer(
        name="WebPenTester",
        model_client=OpenAIChatCompletionClient(model="gpt-4o"),  # Hardcoded to gpt-4o
    )

    # --- SQLi Expert Critic Agent with knowledge base ---
    critic_system_message = (
        "You are a web application penetration testing expert. "
        "You have access to a general pentesting knowledge base via the query_rag_function_tool(query) for reference and advice.\n"
        "Your role is to guide the PenTester_Surfer agent in exploiting vulnerabilities (including but not limited to SQLi) to find a flag or demonstrate impact.\n"
        "When the PenTester_Surfer describes the webpage or its intended actions: "
        "1. Analyze the current state (page content, previous results, error messages). "
        "2. If the PenTester_Surfer encounters element identification errors, guide them to: "
        "   - First take a screenshot to see the current page state "
        "   - Look for form elements by examining the page content "
        "   - Try different selectors (by name, class, or visible text) instead of just IDs "
        "   - Use click_text() for buttons/links instead of click_id() when IDs aren't available "
        "3. Suggest specific payloads or strategies for common web vulnerabilities: "
        "   - SQL injection (tautologies, UNION SELECT, error-based, blind, etc.) "
        "   - XSS (cross-site scripting) payloads and detection methods "
        "   - Command injection, SSRF, IDOR, and other common web vulns "
        "   - Use the query_rag_function_tool(query) to look up techniques, payloads, or explanations as needed.\n"
        "4. Help interpret any error messages from the website in the context of web vulnerabilities. "
        "5. If the PenTester_Surfer seems stuck or is trying ineffective methods, provide clear alternative steps. "
        "6. If form filling fails, suggest alternative approaches like: "
        "   - Using fill_text() with visible field labels "
        "   - Taking a screenshot first to identify correct selectors "
        "   - Looking for form elements in the page source "
        "Always provide specific, actionable guidance. Also, suggest tool calls and function calls to the planner agent if necessary that will help the web agent learn things or even get into the site itself.\n"
        "Use query_rag_function_tool(query) to answer any general pentesting or vulnerability questions.\n"
        "Upon end say TERMINATE"
    )
    sqli_expert_agent = AssistantAgent(
        name="SQLiExpert",
        model_client=model_client_gpt4o,
        system_message=critic_system_message,
        tools=[query_rag_function_tool]
    )

    # --- Team ---
    selector_prompt = """Select an agent to perform task.

    {roles}

    Current conversation context:
    {history}

    Read the above conversation, then select an agent from {participants} to perform the next task.
    Make sure the planner agent has assigned tasks before other agents start working.
    Only select one agent.
    """
    team = SelectorGroupChat(
    [recon_planner_agent, web_pentester_agent, sqli_expert_agent],
    model_client=model_client_gpt4o,
    termination_condition=termination,
    selector_prompt=selector_prompt,
    allow_repeated_speaker=True,  # Allow an agent to speak multiple turns in a row.
    )

    # --- Interactive Loop ---
    print("\n[Interactive Mode] Starting agent team on user-supplied URLs...")
    for url in target_urls:
        print(f"\n[Target] {url}")
        # Compose a task for the team
        task = (
            f"Target URL: {url}\n"
            f"Planner: Plan the SQL injection attack and request any tools you need.\n"
            f"Web Surfer: Execute web actions as needed.\n"
            f"NO YAPPING AND NO UNNECESSARY SPEECH OR ACTIONS SAY ONLY NECESSARY INFORMATION, DO NOT REPEAT WHAT OTHER BOTS SAY. GIVE SPECIFIC AND ACTIONABLE INSTRUCTIONS NOT GENERAL ADVICE"
            f"Work together to execute an sql injection. If a tool is needed, the planner should make the tool call and announce it."
        )
        try:
            stream = team.run_stream(task=task)
            await Console(stream)
        except KeyboardInterrupt:
            print("\n--- Test interrupted by user ---")
            break
        except Exception as e:
            print(f"An error occurred during the agent run: {e}")
            print("The agents will attempt to recover and continue.")
    print("\n--- Test Finished. Closing browser... ---")
    try:
        await web_pentester_agent.close()
        print("Browser closed.")
    except Exception as e:
        print(f"Error closing browser: {e}")

if __name__ == "__main__":
    asyncio.run(main())