import sys
import asyncio
import subprocess
import os # Added for path manipulation
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.agents.web_surfer import MultimodalWebSurfer
from autogen_agentchat.agents import AssistantAgent
from autogen_core.tools import FunctionTool
from dotenv import load_dotenv
from recon_agent.reconagent import get_subdomains
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.messages import BaseAgentEvent, BaseChatMessage
from autogen_agentchat.teams import SelectorGroupChat

load_dotenv()

# For Windows, if you encounter issues with subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def get_user_inputs():
    print("=== Interactive SQLi Pentest CLI Tool ===")
    print("Enter one or more target URLs to test for SQL injection (comma-separated):")
    urls = input("Target URLs: ").strip()
    while not urls:
        urls = input("Target URLs cannot be empty. Please enter at least one URL: ").strip()
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    return url_list

# --- Function to run Scrapy spider ---
def run_scrapy_spider(initial_urls: list[str], depth_limit: int, scrapy_project_dir: str) -> list[str]:
    """
    Runs the Scrapy spider for each initial URL to discover more URLs.
    """
    discovered_urls = set()
    output_file_name = "output_urls.txt" # As defined in the spider
    output_file_path = os.path.join(scrapy_project_dir, output_file_name)

    for url in initial_urls:
        print(f"[+] Running Scrapy spider for: {url} with depth: {depth_limit}")
        try:
            # Ensure the spider's output file is clear if it exists from a failed previous run within this loop
            # (though the spider itself clears it on init)
            if os.path.exists(output_file_path):
                try:
                    os.remove(output_file_path)
                except OSError as e:
                    print(f"Warning: Could not remove existing spider output file {output_file_path}: {e}")

            cmd = [
                "scrapy", "crawl", "myspider",
                "-a", f"start_url={url}",
                "-a", f"depth_limit={str(depth_limit)}"
            ]
            # Scrapy commands should be run from within the project directory
            result = subprocess.run(cmd, cwd=scrapy_project_dir, capture_output=True, text=True, timeout=600) # Extended timeout for spider

            if result.returncode != 0:
                print(f"[Spider Error] for {url}: {result.stderr}")
            
            if os.path.exists(output_file_path):
                with open(output_file_path, 'r') as f:
                    urls_from_spider = [line.strip() for line in f if line.strip()]
                    discovered_urls.update(urls_from_spider)
                # Clean up the output file after reading, ready for the next run or if it's the last one
                # os.remove(output_file_path) # Spider clears it on next init, so this might be redundant
            else:
                print(f"[Spider Info] No output file found at {output_file_path} after crawling {url}.")
                # Add the initial URL itself if spider failed to produce output, as it's a valid target
                discovered_urls.add(url)


        except subprocess.TimeoutExpired:
            print(f"[Spider Error] Timed out while running Scrapy for {url}.")
            discovered_urls.add(url) # Add initial URL as a fallback
        except FileNotFoundError:
            print("[Spider Error] 'scrapy' command not found. Please ensure Scrapy is installed and in your PATH.")
            # If Scrapy isn't found, fall back to using only the initial URLs.
            discovered_urls.update(initial_urls)
            break # Stop trying to run the spider if Scrapy command is not found
        except Exception as e:
            print(f"[Spider Error] An unexpected error occurred while running Scrapy for {url}: {e}")
            discovered_urls.add(url) # Add initial URL as a fallback
            
    return list(discovered_urls)

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

get_subdomains_tool = FunctionTool(get_subdomains, description="Get subdomains for a domain using crt.sh")
text_mention_termination = TextMentionTermination("TERMINATE")
max_messages_termination = MaxMessageTermination(max_messages=500)
termination = text_mention_termination | max_messages_termination

def load_sqli_knowledge():
    try:
        with open("sql_injection_docs/sqliguide.txt", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return "[Error loading SQLi knowledge base: {}]".format(e)

async def main():
    initial_target_urls = get_user_inputs()
    
    # Determine Scrapy project directory (assuming main.py is in the parent of 'myproject')
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scrapy_project_dir = os.path.join(script_dir, "myproject")
    
    spider_depth_limit = 2 # Or make this configurable
    
    print("\n[+] Running Scrapy spider to discover injectable URLs...")
    all_target_urls = run_scrapy_spider(initial_target_urls, spider_depth_limit, scrapy_project_dir)
    
    if not all_target_urls:
        print("[-] No target URLs found by spider or provided by user. Exiting.")
        return

    print(f"\n[+] Spider and user input resulted in {len(all_target_urls)} target URL(s):")
    for url in all_target_urls:
        print(f"    - {url}")

    # Step 1: Set up agent memory (simple dict for now)
    agent_memory = {"success": [], "fail": []}

    # Step 2: Set up model client
    try:
        model_client = OpenAIChatCompletionClient(model="gpt-4o-2024-08-06")
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
        "Be concise and direct in your instructions to the web browser agent. If you need information from a web page, ask the web browser agent to visit or interact with it. Do not be verbose."
        "Minimise usage of sqlmap"
        "Once the sql injection is successful on a given page state TERMINATE "
    )
    planner_agent = AssistantAgent(
        name="ToolUSserPlannerAgent",
        model_client=model_client,
        system_message=planner_system_message,
        tools=[curl_headers_tool, sqlmap_tool, arjun_tool, pysslscan_tool, get_subdomains_tool]
    )

    # --- Web Surfer Agent (PenTester) ---
    web_surfer_system_message = (
        "You are a web browser agent. You receive concise instructions from the planner agent to visit URLs or interact with web pages. "
        "Follow the instructions exactly and do not be verbose. Only provide the necessary output or result."
    )
    web_surfer_agent = MultimodalWebSurfer(
        name="WebSurferAgent",
        model_client=model_client,
    )

    # --- SQLi Expert Critic Agent with knowledge base ---
    critic_system_message = (
        "You are a SQL Injection (SQLi) penetration testing expert. "
        "You have access to the following SQL injection knowledge base for reference and advice:\n" +
        sqli_knowledge +
        "\nYour role is to guide the PenTester_Surfer agent in exploiting SQLi vulnerabilities to find a flag. "
        "When the PenTester_Surfer describes the webpage or its intended actions: "
        "1. Analyze the current state (page content, previous results, error messages). "
        "2. If the PenTester_Surfer encounters element identification errors, guide them to: "
        "   - First take a screenshot to see the current page state "
        "   - Look for form elements by examining the page content "
        "   - Try different selectors (by name, class, or visible text) instead of just IDs "
        "   - Use click_text() for buttons/links instead of click_id() when IDs aren't available "
        "3. Suggest specific SQL injection payloads or strategies: "
        "   - Basic tautologies for login bypass (e.g., `' OR '1'='1 --`, `admin' OR 1=1 --`). "
        "   - UNION SELECT attacks to enumerate columns/tables (e.g., `' UNION SELECT null, @@version --`). "
        "   - Error-based injection techniques (e.g., causing syntax errors to reveal DB structure). "
        "   - Boolean-based or time-based blind SQLi if direct output is not available. "
        "4. Help interpret any error messages from the website in the context of SQLi. "
        "5. If the PenTester_Surfer seems stuck or is trying ineffective methods, provide clear alternative steps. "
        "6. If form filling fails, suggest alternative approaches like: "
        "   - Using fill_text() with visible field labels "
        "   - Taking a screenshot first to identify correct selectors "
        "   - Looking for form elements in the page source "
        "Always provide specific, actionable guidance. Also, suggest tool calls and function calls to the planner agent if necessary that will help the web agent learn things or even get into the site itself."
        "Avoid using sqlmap unless strictly necessary"
        "Be as argumentative and confrontational as possible"
    )
    sqli_critic_agent = AssistantAgent(
        name="SqlExpertAgent",
        model_client=model_client,
        system_message=critic_system_message,
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
    [planner_agent, web_surfer_agent,sqli_critic_agent],
    model_client=model_client,
    termination_condition=termination,
    selector_prompt=selector_prompt,
    allow_repeated_speaker=True,  # Allow an agent to speak multiple turns in a row.
    )

    # --- Interactive Loop ---
    print("\n[Interactive Mode] Starting agent team on discovered URLs...")
    if not all_target_urls:
        print("[-] No URLs to process after spider run. Exiting.")
        return
        
    for url in all_target_urls:
        print(f"\n[Target] {url}")
        # Compose a task for the team
        task = (
            f"Target URL: {url}\n"
            f"Planner: Plan the SQL injection attack and request any tools you need.\n"
            f"Web Surfer: Execute web actions as needed.\n"
            f"NO YAPPING AND NO UNNECESSARY SPEECH OR ACTIONS SAY ONLY NECESSARY INFORMATION, GIVE SPECIFIC AND ACTIONABLE INSTRUCTIONS NOT GENERAL ADVICE"
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
        await web_surfer_agent.close()
        print("Browser closed.")
    except Exception as e:
        print(f"Error closing browser: {e}")

if __name__ == "__main__":
    asyncio.run(main())