import sys
import asyncio
import subprocess
import signal
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.agents.web_surfer import MultimodalWebSurfer
from autogen_agentchat.agents import AssistantAgent
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
from langchain.vectorstores import FAISS
import base64
from io import BytesIO
from PIL import Image
import time
from datetime import datetime, timedelta
import argparse
from typing import List, Dict, Any
from autogen_ext.tools.mcp import SseServerParams, mcp_server_tools  # Burp Suite MCP integration
from autogen_core.memory import ListMemory, MemoryContent, MemoryMimeType
from autogen_core.model_context import BufferedChatCompletionContext
from src.utils.state_tracking import PenTestState, SQLiTestState
from state_persistence import load_state, save_state
from test_sequences import TestManager
from hashlib import md5
from urllib.parse import urlparse
import re
from tools import summarise_http_response, summarise_arjun_output, bypasspayloads, parse_burp_response  # local helper
from src.contextplus_memory import CompressedThrottledMemory

# (Auto-injection logic deprecated; planners now craft full requests manually.)

def load_config():
    """Load configuration from config.txt file."""
    config = {}
    with open('config.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Handle different value types
                    if value.startswith('[') and value.endswith(']'):
                        # Parse list
                        value = json.loads(value)
                    elif value.startswith('{') and value.endswith('}'):
                        # Parse dictionary
                        value = json.loads(value)
                    elif value.lower() in ('true', 'false'):
                        # Parse boolean
                        value = value.lower() == 'true'
                    elif value.isdigit():
                        # Parse integer
                        value = int(value)
                    elif value.startswith('"') and value.endswith('"'):
                        # Parse string with quotes
                        value = value[1:-1]
                    
                    config[key] = value
    return config

# Load configuration
config = load_config()

# Use configuration values
planner_system_message = config['PLANNER_SYSTEM_MESSAGE']
selector_system_message = config['SELECTOR_SYSTEM_MESSAGE']
tool_usage_guidelines = config['TOOL_USAGE_GUIDELINES']
communication_rules = config['COMMUNICATION_RULES']
webpentester_rules = config['WEBPENTESTER_RULES']
planner_strategies = config['PLANNER_STRATEGIES']
short_planner_sys_msg = config.get('SHORT_PLANNER_SYSTEM_MESSAGE')

# Import all tool functions
from tools import (
    run_curl_headers, run_sqlmap, arjun_scan, pysslscan_scan,
    aquatone_scan, summarize_aquatone_output,
    knockpy_scan, summarize_knockpy_output,
    run_ffuf, run_wapiti, read_wapiti_report,
    save_image_to_temp, google_custom_search, search_security_sites,
    writereport,
)
try:
    from autogen_ext.models.gemini import GeminiChatCompletionClient  # type: ignore
except ImportError:  # Provide dummy mapping if library missing
    GeminiChatCompletionClient = OpenAIChatCompletionClient  # type: ignore

# For Windows, if you encounter issues with subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def get_user_inputs():
    print("=== Interactive SQLi Pentest CLI Tool ===")
    print("Choose AI model:")
    print("1. o3-mini (Recommended)")
    print("2. o4-mini (Experimental)")
    print("3. gpt-4.1-mini")
    print("4. gpt-4o-mini")
    print("5. gpt-4.1-nano")
    print("6. gemini-2.0-flash")
    
    model_choice = input("Please enter your choice (1-6): ").strip()
    model_map = {
        "1": "o3-mini",
        "2": "o4-mini",
        "3": "gpt-4.1-mini",
        "4": "gpt-4o-mini",
        "5": "gpt-4.1-nano",
        "6": "gemini-2.0-flash"
    }
    
    model_name = model_map.get(model_choice, "o3-mini")
    
    print("\nEnter one or more target URLs to test for SQL injection (comma-separated)(Insert the exact URL you want,no trailers like /index.html):")
    urls = input("Target URLs: ").strip()
    while not urls:
        urls = input("Target URLs cannot be empty. Please enter at least one URL: ").strip()
    url_list = [u.strip() for u in urls.split(",") if u.strip()]

    print("\nAdvanced Tools Configuration:")
    print("The following tools require additional setup and may take longer to run:")
    print("1. SQLMap (SQL injection testing)")
    print("2. Wapiti (Web vulnerability scanner)")
    print("3. FFUF (Directory/parameter fuzzing)")
    print("4. Aquatone (Visual reconnaissance)")
    
    tool_choice = input("\nWould you like to enable these advanced tools? (y/n): ").strip().lower()
    enabled_tools = list(TOOL_NAME_MAP.keys())
    
    if tool_choice != 'y':
        # Remove advanced and high-token tools if not enabled
        disabled_tools = [
            'sqlmap_tool', 'wapiti_tool', 'read_wapiti_report_tool', 'ffuf_tool',
            'aquatone_tool', 'summarize_aquatone_tool',
            'google_search_tool', 'security_sites_search_tool', 'query_rag_function_tool'
        ]
        enabled_tools = [tool for tool in enabled_tools if tool not in disabled_tools]
    
    # ----------------------------------------------------------
    # Context window configuration (controls how many messages
    # each agent keeps in its immediate buffer). Larger values
    # consume more tokens but provide broader conversational
    # context for the LLM. The default (8) is usually sufficient.
    # ----------------------------------------------------------

    print("\nContext window options (controls how many recent messages each agent sees):")
    print("1. Summary (keep last 8 messages) – recommended")
    print("2. Extended (keep last 40 messages)")
    print("3. Custom value")

    ctx_choice = input("Select an option (1-3): ").strip()
    if ctx_choice == "2":
        context_window_size = 40
    elif ctx_choice == "3":
        custom_val = input("Enter desired buffer size (≥4): ").strip()
        try:
            context_window_size = max(4, int(custom_val))
        except ValueError:
            print("Invalid number, falling back to 8.")
            context_window_size = 8
    else:
        context_window_size = 8  # Default summary mode

    # ----------------------------------------------------------
    # Task objective customisation (default admin login bypass)
    # ----------------------------------------------------------

    print("\nPrimary objective (default: gain admin access via SQL injection)")
    obj = input("Describe the end-goal (press Enter to keep default): ").strip()
    if not obj:
        obj = "Gain admin access via SQL injection. "

    return url_list, model_name, enabled_tools, context_window_size, obj

# Create enhanced FunctionTools with improved descriptions
curl_headers_tool = FunctionTool(run_curl_headers, description="Run to get HTTP headers and subdomains. Use for initial reconnaissance ONLY, after initial recon steps do not run any more")
sqlmap_tool = FunctionTool(run_sqlmap, description="Run advanced SQLMap scan with level 2 risk 2 for SQL injection detection. Returns structured vulnerability report.")
bypasspayloads_tool = FunctionTool(bypasspayloads, description="Return up to 10 classic admin-login SQL-injection payloads. Use format_type='json' for Burp Intruder (JSON array), or 'text' for manual testing.")
def arjun_summary(
    url: str = None,
    textFile: str = None,
    wordlist: str = None,
    method: str = None,
    rateLimit: int = 9999,
    chunkSize: int = None,
) -> str:
    """Run Arjun and return a brief summary (last 30 words)."""
    raw = arjun_scan(
        url=url,
        textFile=textFile,
        wordlist=wordlist,
        method=method,
        rateLimit=rateLimit,
        chunkSize=chunkSize,
    )
    return summarise_arjun_output(raw)

arjun_tool = FunctionTool(
    arjun_summary,
    name="arjun_tool",
    description="Discover hidden HTTP parameters using Arjun (returns concise summary).",
)

pysslscan_tool = FunctionTool(pysslscan_scan, description="Scan SSL/TLS configuration for vulnerabilities and weak ciphers.")
aquatone_tool = FunctionTool(aquatone_scan, description="Take screenshots and analyze web applications visually. Requires Chrome path.")
summarize_aquatone_tool = FunctionTool(summarize_aquatone_output, description="Parse and summarize Aquatone JSON results with host and URL discoveries.")
knockpy_tool = FunctionTool(knockpy_scan, description="Perform subdomain enumeration using KnockPy with wordlist fuzzing.")
summarize_knockpy_tool = FunctionTool(summarize_knockpy_output, description="Summarize KnockPy's output from a given output directory. Returns a summary of discovered subdomains and interesting metadata.")
ffuf_tool = FunctionTool(run_ffuf, description="Fast directory/file/parameter fuzzing with smart filtering. Use common-dirs or big.txt wordlists.")
wapiti_tool = FunctionTool(run_wapiti, description="Comprehensive web vulnerability scanner for XSS, SQLi, file inclusion, etc.")
read_wapiti_report_tool = FunctionTool(read_wapiti_report, description="Parse and summarize Wapiti scan results with vulnerability details.")

get_subdomains_tool = FunctionTool(get_subdomains, description="Get subdomains for target domain using certificate transparency logs (crt.sh)")
google_search_tool = FunctionTool(google_custom_search, description="Search Google for current penetration testing techniques, payloads, and security information. Use for real-time knowledge.")
security_sites_search_tool = FunctionTool(search_security_sites, description="Search multiple security websites (PortSwigger, OWASP, CVE, Exploit-DB) for comprehensive vulnerability information.")
text_mention_termination = TextMentionTermination("TERMINATE")  # manual cancel keyword
terminate_keyword_termination = TextMentionTermination("TERMINATE")
max_messages_termination = MaxMessageTermination(max_messages=205)
termination = terminate_keyword_termination | max_messages_termination

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
    Enhanced RAG query function with preprocessing and query expansion.
    - query: The question or topic to look up.
    Returns the RAG app's response with improved query processing.
    """
    # Preprocess and expand the query for better results
    processed_query = preprocess_query(query)
    
    if processed_query in rag_query_cache:
        return rag_query_cache[processed_query]
    
    try:
        result = query_rag(processed_query)
        rag_query_cache[processed_query] = result
        save_rag_cache()
        return result
    except Exception as e:
        return f"[query_rag_tool error] {e}"

def preprocess_query(query: str) -> str:
    """
    Preprocess and expand queries for better RAG retrieval.
    """
    query = query.strip()
    
    # Query expansion based on common penetration testing patterns
    expansions = {
        "login": "login authentication bypass credentials admin",
        "sqli": "sql injection payload union select database",
        "xss": "cross site scripting javascript payload",
        "directory": "directory traversal path fuzzing enumeration",
        "file upload": "file upload vulnerability shell webshell",
        "rce": "remote code execution command injection",
        "lfi": "local file inclusion path traversal",
        "rfi": "remote file inclusion payload",
        "csrf": "cross site request forgery token bypass",
        "ssti": "server side template injection payload",
        "admin": "admin panel dashboard login administrator",
        "default": "default credentials password username",
        "bypass": "authentication bypass login security",
        "enumerate": "enumeration discovery reconnaissance",
        "exploit": "exploit payload vulnerability attack"
    }
    
    # Expand query if it contains key terms
    for key, expansion in expansions.items():
        if key.lower() in query.lower():
            query += f" {expansion}"
            break
    
    # Add context for better retrieval
    if not any(term in query.lower() for term in ["how", "what", "where", "when", "why"]):
        query = f"How to {query}"
    
    return query

query_rag_function_tool = FunctionTool(query_rag_tool, description="Query enhanced RAG system for specific penetration testing knowledge, payloads, and techniques. Use detailed queries.")

# Create writereport tool
writereport_tool = FunctionTool(writereport, description="Write final penetration testing report to a text file. Provide filename (without .txt) and full report content.")

class ImageEnabledMessageHandler:
    """Message handler that can handle both text and image data"""
    def __init__(self, base_handler):
        self.base_handler = base_handler
        self.temp_files = []

    def handle_agent_message(self, agent_name, message):
        """Handle text or image messages gracefully."""
        try:
            from PIL.Image import Image as PILImage  # type: ignore
        except ImportError:
            PILImage = None  # noqa

        # Case 1: message is a dict with separate image field
        if isinstance(message, dict) and 'image' in message:
            image_path = save_image_to_temp(message['image'])
            self.temp_files.append(image_path)
            text_message = f"{message.get('text', '')}\n[Image saved to: {image_path}]"
            self.base_handler.handle_agent_message(agent_name, text_message)
            return

        # Case 2: message is a raw PIL Image or bytes
        if (PILImage and isinstance(message, PILImage)) or isinstance(message, (bytes, bytearray)):
            image_path = save_image_to_temp(message)
            self.temp_files.append(image_path)
            self.base_handler.handle_agent_message(agent_name, f"[Image saved to: {image_path}]")
            return

        # Fallback: convert to string to avoid JSON serialisation errors
        try:
            self.base_handler.handle_agent_message(agent_name, str(message))
        except Exception:
            # Last resort: just note unsupported message type
            self.base_handler.handle_agent_message(agent_name, "[Unsupported message type ignored]")

    def handle_tool_call(self, agent_name, tool_name, args):
        self.base_handler.handle_tool_call(agent_name, tool_name, args)
    
    def handle_tool_result(self, agent_name, tool_name, result):
        self.base_handler.handle_tool_result(agent_name, tool_name, result)
    
    def handle_error(self, error_message):
        self.base_handler.handle_error(error_message)
    
    def cleanup(self):
        """Clean up temporary image files"""
        for temp_file in self.temp_files:
            try:
                os.remove(temp_file)
            except:
                pass
        self.temp_files = []

class WebErrorHandler:
    """Handles web-related errors and provides recovery mechanisms"""
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    @staticmethod
    async def retry_with_backoff(func, *args, **kwargs):
        """Retry a function with exponential backoff"""
        last_exception = None
        for attempt in range(WebErrorHandler.MAX_RETRIES):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < WebErrorHandler.MAX_RETRIES - 1:
                    delay = WebErrorHandler.RETRY_DELAY * (2 ** attempt)
                    print(f"Web operation failed, retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
        return f"Operation failed after {WebErrorHandler.MAX_RETRIES} attempts. Last error: {last_exception}"

# Mapping of tool names to FunctionTool objects for easy selection
TOOL_NAME_MAP = {
    'curl_headers_tool': curl_headers_tool,
    'sqlmap_tool': sqlmap_tool,
    'arjun_tool': arjun_tool,
    'pysslscan_tool': pysslscan_tool,
    'aquatone_tool': aquatone_tool,
    'summarize_aquatone_tool': summarize_aquatone_tool,
    'knockpy_tool': knockpy_tool,
    'summarize_knockpy_tool': summarize_knockpy_tool,
    'ffuf_tool': ffuf_tool,
    'wapiti_tool': wapiti_tool,
    'read_wapiti_report_tool': read_wapiti_report_tool,
    'get_subdomains_tool': get_subdomains_tool,
    'google_search_tool': google_search_tool,
    'security_sites_search_tool': security_sites_search_tool,
    'query_rag_function_tool': query_rag_function_tool,
    'bypasspayloads_tool': bypasspayloads_tool,
    'writereport_tool': writereport_tool,
}

# Remove tools overlapped by BurpSuite MCP (active scan & SQLi testing)
REMOVED_TOOLS = {"sqlmap_tool", "wapiti_tool", "read_wapiti_report_tool", "knockpy_tool", "summarize_knockpy_tool"}
for t in REMOVED_TOOLS:
    TOOL_NAME_MAP.pop(t, None)

# ------------- Safe retry wrapper for chat client -------------

class RetryChatClient(OpenAIChatCompletionClient):
    """Tries primary model first, falls back to gpt-4.1-mini on failure."""

    def __init__(self, primary_model: str, fallback_model: str = "gpt-4.1-mini", **kwargs):
        super().__init__(model=primary_model, **kwargs)
        self._primary = primary_model
        self._fallback = fallback_model

    async def create(self, *args, **kwargs):  # type: ignore
        try:
            return await super().create(*args, **kwargs)
        except Exception:
            # Switch to fallback once
            if self.model != self._fallback:
                self.model = self._fallback
                return await super().create(*args, **kwargs)
            raise

def get_model_client(model_name: str):
    # Use retry wrapper only when primary is o3-mini
    if model_name == "o3-mini":
        return RetryChatClient(primary_model="o3-mini")
    return OpenAIChatCompletionClient(model=model_name)

# Selector prompt for a three-agent team with two debating planners
selector_prompt = """Select an agent for the next task based on the conversation history.
{roles}
Current conversation:
{history}
1.  After a planner (PlannerAlpha or PlannerBeta) speaks, the other planner should respond to debate the plan.
2.  If the planners have reached a consensus on a specific instruction for the WebPenTester, select WebPenTester to execute it.
3.  After WebPenTester executes a task or reports an error, select one of the planners to analyze the outcome and propose the next step.
4.  Always prioritize continuing the debate between planners until a clear, single action for the WebPenTester is agreed upon.
5.  Avoid selecting the same agent twice in a row unless they are processing the result of a tool call.
Select one agent from {participants}.
"""

# ---------------- Throttled memory wrapper ----------------
class ThrottledListMemory(ListMemory):
    """ListMemory variant that only returns search results every Nth query call.

    This reduces costly memory retrieval events that bloat token usage."""

    def __init__(self, throttle: int = 3, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._throttle = max(1, throttle)
        self._counter = 0

    async def query(self, query_text: str, *args, **kwargs):  # type: ignore
        self._counter += 1
        if self._counter % self._throttle != 0:
            # Skip retrieval this turn to save tokens
            return []
        results = await super().query(query_text, *args, **kwargs)
        # Truncate each text memory to 120 chars max to save tokens
        for r in results:
            if isinstance(r.content, str) and len(r.content) > 120:
                r.content = r.content[:120] + "..."
        return results

# ----------------- URL scope helpers -----------------

def _compute_path_prefix(target_url: str) -> str:
    """Return the path prefix that defines in-scope navigation.

    If the user supplied a deep path like /problem/53751/abc, we keep the directory
    part (/problem/53751/) so the agent can still navigate within that subtree.
    For bare root URLs, the prefix is just "/" (no restriction)."""
    parsed = urlparse(target_url)
    path = parsed.path or "/"

    # Root path remains unrestricted
    if path == "/":
        return "/"

    # If the last segment looks like a file (contains a dot) keep the full path
    last_seg = path.split("/")[-1]
    if "." in last_seg:
        return path if path.startswith("/") else "/" + path

    # Otherwise return directory prefix with trailing slash
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return path

def in_scope(candidate_url: str, base_host: str, path_prefix: str) -> bool:
    """True if candidate_url is within the same host and under path_prefix."""
    try:
        p = urlparse(candidate_url)
        if p.netloc != base_host:
            return False

        # Exact file path restriction (prefix without trailing slash)
        if not path_prefix.endswith("/"):
            return p.path == path_prefix

        # Directory scope restriction
        return p.path.startswith(path_prefix)
    except Exception:
        return False

# Cache for Burp Suite MCP tools to avoid repeated SSE negotiation
_BURP_TOOLS_CACHE: dict[str, list] = {}

async def run_pentest_team(
    target_urls: list[str],
    message_handler=None,
    cancel_event=None,
    # Model customisation (defaults now use gpt-4.1-mini)
    planner_model: str = "gpt-4.1-mini",
    web_model: str = "gpt-4.1-mini",
    # Prompt overrides
    planner_prompt_override: str | None = None,
    selector_prompt_override: str | None = None,
    # Tool selection
    tool_names: list[str] | None = None,
    # Context buffer size (number of recent messages to keep)
    context_window_size: int = 8,
    # Objective
    objective: str = "Gain admin access via SQL injection.",
):
    """Run the pentest team with two debating planners."""
    if message_handler:
        message_handler = ImageEnabledMessageHandler(message_handler)

    # Initialize state tracking (load previous run if exists)
    loaded = load_state()
    pentest_state = PenTestState.from_dict(loaded) if loaded else PenTestState()
    sqli_state = SQLiTestState()
    test_manager = TestManager()

    # Re-enable all tools or use the provided selection
    if tool_names:
        selected_tools = [TOOL_NAME_MAP[name] for name in tool_names if name in TOOL_NAME_MAP]
    else:
        selected_tools = list(TOOL_NAME_MAP.values())

    try:
        start_time_total = time.time()

        if message_handler:
            message_handler.handle_agent_message("SYSTEM", f"[+] Loaded {len(target_urls)} target URL(s): {', '.join(target_urls)}")
        else:
            print(f"[+] Loaded {len(target_urls)} target URL(s):")
            for url in target_urls:
                print(f"    - {url}")

        # Step 1: Set up model clients for each agent
        try:
            planner_client = get_model_client(planner_model)
            web_client = get_model_client(web_model)
        except Exception as e:
            error_msg = f"Error initializing model client(s): {e}\nPlease ensure your API keys are set correctly."
            if message_handler:
                message_handler.handle_error(error_msg)
            else:
                print(error_msg)
            return

        # --- Lightweight guide compression to save tokens ---
        def _compress_guide(text: str, max_lines: int = 60) -> str:
            """Return a condensed version of a lengthy guide by keeping only short or bullet lines."""
            lines = [l.strip() for l in text.splitlines()]
            kept: list[str] = []
            for l in lines:
                if not l:
                    continue
                if l.startswith(('-', '*', '#')) or len(l) <= 100:
                    kept.append(l)
                if len(kept) >= max_lines:
                    break
            return '\n'.join(kept)

        # ------------------ Shared long-term memory ------------------
        fundamental_memory = CompressedThrottledMemory(throttle=3)

        # Lightweight note-taking tool for planners
        async def add_note_tool(note: str) -> str:
            """Persist a short site-specific note in shared memory (prefix NOTE::)."""
            await fundamental_memory.add(
                MemoryContent(content=f"NOTE::{note}", mime_type=MemoryMimeType.TEXT)
            )
            return "Note saved."

        note_tool = FunctionTool(add_note_tool, name="add_note_tool", description="Store an ad-hoc observation or strategy note into team memory (NOTE:: prefix) so it can be retrieved later.")

        # Helper to push a concise state overview into memory
        async def _update_overview():
            """Store a one-liner summary of current counts in memory for quick retrieval."""
            await fundamental_memory.add(
                MemoryContent(
                    content=(
                        f"Current Phase: {pentest_state.current_phase}\n"
                        f"Tested Endpoints: {len(pentest_state.tested_endpoints)}\n"
                        f"Promising Endpoints: {len(pentest_state.promising_endpoints)}\n"
                        f"Confirmed Vulnerabilities: {len(pentest_state.confirmed_vulns)}"
                    ),
                    mime_type=MemoryMimeType.TEXT,
                )
            )
            # Pin primary objective reminder so planners never forget the goal
        await fundamental_memory.add(
            MemoryContent(
                    content="TASK_REMINDER::Primary objective: gain admin access. Locate login/auth forms and confirm SQL injection via Burp SQLi scan (prioritise login-bypass vectors).",
                    mime_type=MemoryMimeType.TEXT,
            )
        )
        await _update_overview()

        # --- Fetch Burp Suite MCP tools (PlannerBeta only, cached) ---
        burp_server_params = SseServerParams(url="http://127.0.0.1:9876/sse", headers={})
        cache_key = burp_server_params.url
        if cache_key not in _BURP_TOOLS_CACHE:
            _BURP_TOOLS_CACHE[cache_key] = await mcp_server_tools(burp_server_params)
        burp_tools = _BURP_TOOLS_CACHE[cache_key]

        # --------- Patch verbose Burp tools to trim output ---------
        def _wrap_trim(tool, current_path_prefix: str = "/"):
            """Return a new FunctionTool that trims verbose HTTP responses via summarise_http_response."""
            import inspect, json

            orig_call = tool

            def _extract_text(payload):
                if payload is None:
                    return ""

                # If payload is JSON string representing list[dict], decode first
                if isinstance(payload, str):
                    try:
                        data = json.loads(payload)
                    except json.JSONDecodeError:
                        return payload  # Raw string already
                else:
                    data = payload

                # Expect Burp plugin shape: list → first → 'text'
                if isinstance(data, list) and data:
                    first = data[0]
                    if isinstance(first, dict):
                        return first.get("text", str(payload))
                return str(payload)

            async def _await_and_trim(awaitable):
                raw = await awaitable
                # Extract URL from the request for better context
                url_context = ""
                try:
                    # Try to extract URL from the raw response or request
                    if "Host:" in str(raw):
                        host_match = re.search(r"Host:\s*([^\r\n]+)", str(raw))
                        if host_match:
                            url_context = f"https://{host_match.group(1).strip()}"
                except:
                    pass
                raw_text = _extract_text(raw)
                parsed = parse_burp_response(raw_text)
                return summarise_http_response(parsed, url=url_context)

            def _wrapper(*args, **kwargs):
                # Pre-send hygiene for Repeater/HTTP tools
                if tool.name and tool.name.endswith("send_http1_request"):
                    content_str = kwargs.get("content", "")
                    if content_str:
                        # 1) Ensure friendly User-Agent
                        content_str = content_str.replace("User-Agent: BurpSuite", "User-Agent: Mozilla/5.0")
                        # 2) Ensure the request explicitly closes the connection to avoid server hangs
                        if "Connection:" not in content_str:
                            # insert after request line (first CRLF)
                            first_break = content_str.find("\r\n")
                            if first_break != -1:
                                content_str = content_str[:first_break+2] + "Connection: close\r\n" + content_str[first_break+2:]
                        kwargs["content"] = content_str

                # Call the original tool
                result = orig_call(*args, **kwargs)

                # Helper to grab proxy history tool if available (cached in closure)
                proxy_hist_tool = get_proxy_tool  # from enclosing scope

                # Helper to append payload outcome
                def _analyse_and_note(text: str) -> str:
                    # Record payload outcome when Intruder/Repeater used manually
                    if tool.name and tool.name.endswith("send_to_intruder"):
                        payloads_used: list[str] = []
                        if "payloads" in kwargs and isinstance(kwargs["payloads"], list):
                            payloads_used = kwargs["payloads"]
                        elif "payloadSets" in kwargs and isinstance(kwargs["payloadSets"], list):
                            payloads_used = kwargs["payloadSets"][0]

                        endpoint = "(unknown)"
                        content_req = kwargs.get("content", "")
                        first_line = content_req.split("\n", 1)[0] if content_req else ""
                        if first_line:
                            endpoint = first_line.split(" ")[1] if " " in first_line else first_line

                        success_keywords = ["syntax", "sql", "error", "welcome", "admin", "flag", "id"]
                        lower_text = text.lower()
                        for pl in payloads_used:
                            ok = any(k in lower_text for k in success_keywords)
                            payload_tracker.record(endpoint, pl, ok, note=first_line)

                    return text

                if inspect.iscoroutine(result):
                    async def _combined():
                        base = await _await_and_trim(result)
                        return _analyse_and_note(base)

                    return _combined()
                else:
                    # Extract and parse Burp response immediately
                    raw_burp = _extract_text(result)
                    if "HttpRequestResponse{" in raw_burp:
                        # Use parse_burp_response to extract just the HTTP part
                        raw_resp = parse_burp_response(raw_burp)
                    else:
                        raw_resp = raw_burp
                    
                    # Summarize the HTTP response concisely
                    trimmed = summarise_http_response(raw_resp)
                    
                    # If body extremely short, attempt fallback via proxy history
                    if proxy_hist_tool and len(raw_resp) < 40:
                        try:
                            hist_raw = _extract_text(proxy_hist_tool(count=1, offset=0))
                            if "HttpRequestResponse{" in hist_raw:
                                hist_resp = parse_burp_response(hist_raw)
                            else:
                                hist_resp = hist_raw
                            if len(hist_resp) > len(raw_resp):
                                trimmed = summarise_http_response(hist_resp)
                        except Exception:
                            pass
                    return _analyse_and_note(trimmed)

            from autogen_core.tools import FunctionTool
            return FunctionTool(_wrapper, name=tool.name, description=(tool.description or "") + " (trimmed)")
        wrapped_burp_tools = []
        for _t in burp_tools:
            if _t.name and ("send_http" in _t.name or 
                           _t.name.endswith("create_repeater_tab") or 
                           _t.name.endswith("send_to_intruder")):
                try:
                    wrapped_burp_tools.append(_wrap_trim(_t))
                except Exception:
                    wrapped_burp_tools.append(_t)
            else:
                wrapped_burp_tools.append(_t)
        burp_tools = wrapped_burp_tools

        # --- Partition tools ---
        advanced_names = {"sqlmap_tool", "wapiti_tool", "read_wapiti_report_tool", "ffuf_tool"}
        alpha_tools = [t for t in selected_tools if t.name not in advanced_names]
        beta_tools_extra = [t for t in selected_tools if t.name in advanced_names]
        planner_beta_tools = burp_tools + beta_tools_extra + [note_tool]
        planner_alpha_tools = alpha_tools + [note_tool]
        PERSISTENCE_REM = (
            "You are an autonomous agent — continue until the task is fully solved; never yield early."
        )
        TOOL_REM = (
            "If unsure about page content, DOM structure, or Burp data, call an appropriate TOOL instead of guessing. "
            "Use add_note_tool to store any useful site-specific facts so they persist." 
        )
        PLAN_REM = (
            "Plan briefly before each tool call, and reflect on results before deciding next action."
        )
        CHECKLIST_REM = (
            "##### SCOPE CHECKLIST (fill before EACH tool call)\n"
            "1. Next URL obeys ALLOWED_HOST? ___\n"
            "2. Next URL path starts with ALLOWED_PATH_PREFIX? ___\n"
            "3. Task still matches PRIMARY OBJECTIVE? ___\n"
            "If any answer is 'no', revise plan instead of calling a tool."
        )
        LINK_EXTRACT_REM = (
            "After loading ANY page, immediately run extract_links_from_html on the page's HTML to enumerate navigation/menu links; prioritise those containing login/submit/auth keywords."
        )
        FOCUS_REM = (
            "Focus Rule: Whenever a PROMISING_ENDPOINT exists in memory/state, prioritise confirming it with Burp SQL injection testing before exploring new areas. Do NOT switch tasks until all promising endpoints are either confirmed vulnerable or ruled out."
        )
        allowed_hosts = {urlparse(u).netloc for u in target_urls}
        host_reminder = (
            "\nALLOWED_HOSTS: " + ", ".join(sorted(allowed_hosts)) +
            "\nAlways use one of these exact hosts in any manual HTTP request or Burp action. "
            "Never invent or shorten domain names."
        )

        no_idle_rule = "If you did not call any tool in your previous turn, you MUST call an appropriate tool now; otherwise reply with an empty string."
        termination_rule = (
            "MANDATORY TERMINATION: Only when ADMIN LOGIN BYPASS is conclusively confirmed (e.g., successful redirect, 'welcome', 'dashboard', admin flag shown) "
            "OR you have exhaustively ruled it impossible after testing all payload classes, first use writereport_tool to save a detailed penetration test report, then send ONE message starting with 'FINAL_REPORT::' (≤120 words summarising evidence). "
            "Immediately after the report, output a single line containing ONLY the word 'TERMINATE' (case-exact) and then stop responding. Do NOT send FINAL_REPORT just because an SQL error appeared; you must prove authentication bypass." 
        )
        planner_sys_msg = (
            planner_prompt_override or short_planner_sys_msg or planner_system_message
        ) + "\n" + PERSISTENCE_REM + "\n" + TOOL_REM + "\n" + PLAN_REM + "\n" + CHECKLIST_REM + "\n" + LINK_EXTRACT_REM + "\n" + FOCUS_REM + "\n" + no_idle_rule + "\n" + termination_rule + host_reminder
        bounded_ctx = BufferedChatCompletionContext(buffer_size=context_window_size)
        
        planner_alpha_msg = (
            planner_sys_msg
            + "\n\nYou are PlannerAlpha, the Recon Specialist. Your role is to explore the target, find entry points like login forms, and identify parameters. "
            + "CRITICAL: Always use the exact in-scope path prefix (never bare '/' or parent directories). "
            + "PlannerBeta has advanced tools (Burp Suite, FFUF) for exploitation. Once you find a promising target, clearly define the endpoint, HTTP method, and parameters so PlannerBeta can copy them exactly. "
            + "DO NOT use exploitation tools yourself. When you identify a promising login form, draft a clear, step-by-step set of browser actions (URL, fields, payload) so WebPenTester can perform the SQL-injection manually inside the page. Avoid mentioning send_http1_request – focus on browser interaction. Your final instruction must therefore be a hand-over to PlannerBeta *and* guidance for WebPenTester."
        )
        
        planner_alpha = AssistantAgent(
            name="PlannerAlpha",
            model_client=planner_client,
            system_message=planner_alpha_msg,
            model_context=bounded_ctx,
            tools=planner_alpha_tools,
            memory=[fundamental_memory],
            reflect_on_tool_use=True,
        )

        planner_beta_msg = (
            planner_sys_msg
            + "\n\nYou are PlannerBeta, the Exploitation Specialist. You control BurpSuite MCP tools and advanced scanners. "
            + "CRITICAL: Always use the exact in-scope path prefix (never bare '/' or parent directories). "
            + "When PlannerAlpha hands you a target (an endpoint with method and parameters):\n"
            + "Advise WebPenTester how to carry out SQL-injection directly in the browser: give concrete steps (navigate to URL, fill username/password fields with payload, press submit). Let WebPenTester execute these steps. Use *send_http1_request* only as a fallback when browser interaction fails.\n"
            + "Observe length / status / error messages to confirm injection.\n"
            + "When finished, produce FINAL_REPORT as instructed."
        )
        planner_beta = AssistantAgent(
            name="PlannerBeta",
            model_client=planner_client,
            system_message=planner_beta_msg,
            model_context=bounded_ctx,
            tools=planner_beta_tools,
            memory=[fundamental_memory],
            reflect_on_tool_use=True,
        )

        # --- Web Surfer Agent ---
        web_pentester_agent = MultimodalWebSurfer(
            name="WebPenTester",
            model_client=web_client,
            start_page=target_urls[0] if target_urls else None,
            headless=False,
            use_ocr=True,
        )

        # --- Team Selector Prompt ---
        selector_prompt_final = selector_prompt_override or selector_prompt

        selector_rule_handover = "\nRule 6: If PlannerAlpha provides a clear handover (endpoint, method, params) and suggests PlannerBeta should test it, ALWAYS select PlannerBeta next."
        selector_rule_webpentester = "\nRule 7: Never select WebPenTester unless the last two messages came from different planners who agreed on a single action."

        # --- Team (with two planners and one web surfer) ---
        team = SelectorGroupChat(
            [planner_alpha, planner_beta, web_pentester_agent],
            model_client=planner_client,
            termination_condition=termination,
            selector_prompt=selector_prompt_final + selector_rule_handover + selector_rule_webpentester,
            allow_repeated_speaker=False,
        )

        # --- Interactive Loop ---
        url_timings = {}
        if message_handler:
            message_handler.handle_agent_message("SYSTEM", "[Interactive Mode] Starting agent team...")
        else:
            print("\n[Interactive Mode] Starting agent team on user-supplied URLs...")

        for url in target_urls:
            if cancel_event and cancel_event.is_set():
                break
            start_time_url = time.time()
            
            # Update state for new target
            pentest_state.current_target = url
            pentest_state.current_phase = "recon"
            current_focus = None  # Reset focus endpoint
            
            if message_handler:
                message_handler.handle_agent_message("SYSTEM", f"\n[Target] {url}\n[Time] Starting test...")
            else:
                print(f"\n[Target] {url}")

            # Derive scope variables
            parsed_target = urlparse(url)
            base_host = parsed_target.netloc
            path_prefix = _compute_path_prefix(url)

            def _build_task_desc() -> str:
                focus_line = ""
                if pentest_state.promising_endpoints:
                    nonlocal current_focus
                    current_focus = current_focus or pentest_state.promising_endpoints[0]
                    focus_line = f"CURRENT FOCUS ENDPOINT: {current_focus} (test exhaustively before shifting)\n"
                return (
                    f"Pentest {url}. PRIMARY OBJECTIVE: find the login page (or any credential form) inside the supplied base URL and its sub-paths. CRITICAL: ALWAYS use the FULL path '{path_prefix}' in every request - NEVER use bare '/' or parent paths.\n"
                    f"MANDATORY FIRST ACTION: load the page at EXACTLY '{path_prefix}',run curl_headers_tool to find its subdomains. Stay within '{path_prefix}'.\n"
                    + focus_line +
                    "After locating the login form: enumerate its fields then instruct WebPenTester to attempt SQL-injection manually via browser actions. Provide exact payloads. Use *send_http1_request* only if browser interaction is impossible.  \n"
                    f"Current phase: {pentest_state.current_phase}. Promising={len(pentest_state.promising_endpoints)} Confirmed={len(pentest_state.confirmed_vulns)}.\n"
                    "Replies ≤120 words; statement style."
            )

            task_description = _build_task_desc()

            try:
                if message_handler:
                    stream = team.run_stream(task=task_description)
                    async for event in stream:
                        if cancel_event and cancel_event.is_set():
                            await stream.aclose()
                            break
                        if isinstance(event, BaseChatMessage):
                            message_handler.handle_agent_message(event.source, event.content)
                            
                            # ------------- Scope-aware extraction -------------
                            # Pre-compute host/prefix
                            base_host_cached = base_host
                            prefix_cached = path_prefix

                            # 1) Absolute URLs in message
                            abs_urls = re.findall(r"https?://[^\s'\"<>]+", event.content)
                            for found in abs_urls:
                                if in_scope(found, base_host_cached, prefix_cached):
                                    if found not in pentest_state.promising_endpoints:
                                        pentest_state.promising_endpoints.append(found)
                                        pentest_state.current_phase = "testing"
                                        await fundamental_memory.add(
                                            MemoryContent(content=f"PROMISING_ENDPOINT::{found}", mime_type=MemoryMimeType.TEXT)
                                        )
                                        await _update_overview()
                                        task_description = _build_task_desc()

                            # 2) Extract relative paths from WebPenTester RESULT lines
                            rel_match = re.search(r"RESULT:.*?\s(/[^ \n]+)", event.content)
                            if rel_match:
                                rel_path = rel_match.group(1).strip()
                                full_url = urlparse(url)._replace(path=rel_path, query="", fragment="").geturl()
                                if in_scope(full_url, base_host_cached, prefix_cached):
                                    if full_url not in pentest_state.promising_endpoints:
                                        pentest_state.promising_endpoints.append(full_url)
                                        pentest_state.current_phase = "testing"
                                        await fundamental_memory.add(
                                            MemoryContent(content=f"PROMISING_ENDPOINT::{full_url}", mime_type=MemoryMimeType.TEXT)
                                        )
                                        await _update_overview()
                                        task_description = _build_task_desc()

                            # 2b) Extract form action paths (e.g., login.php) from tool output summaries or conversations
                            for p in re.findall(r"(/[^\s'\"]+\.(?:php|asp|aspx|jsp|html?|cgi))", event.content, re.IGNORECASE):
                                full_url2 = urlparse(url)._replace(path=p, query="", fragment="").geturl()
                                if in_scope(full_url2, base_host_cached, prefix_cached):
                                    if full_url2 not in pentest_state.promising_endpoints:
                                        pentest_state.promising_endpoints.append(full_url2)
                                        pentest_state.current_phase = "testing"
                                        await fundamental_memory.add(
                                            MemoryContent(content=f"PROMISING_ENDPOINT::{full_url2}", mime_type=MemoryMimeType.TEXT)
                                        )
                                        await _update_overview()
                                        task_description = _build_task_desc()

                            # 3) Detect confirmed vulnerability keywords
                            if any(k in event.content.lower() for k in ["success", "vulnerable", "exploited"]):
                                for ep in list(pentest_state.promising_endpoints):
                                    if ep in event.content:
                                        if ep not in pentest_state.confirmed_vulns:
                                            pentest_state.confirmed_vulns.append(ep)
                                            await fundamental_memory.add(
                                                MemoryContent(content=f"CONFIRMED_VULN::{ep}", mime_type=MemoryMimeType.TEXT)
                                            )
                                            await _update_overview()
                                            log_finding(ep, "param", "payload", "vulnerable")

                            # --- Persist final report to file ---
                            if event.content.startswith("FINAL_REPORT::"):
                                try:
                                    with open("report.txt", "w", encoding="utf-8") as rf:
                                        rf.write(event.content.lstrip("FINAL_REPORT::").strip())
                                        rf.write("\n\n=== PAYLOAD SUMMARY ===\n" + payload_tracker.summary())
                                except Exception:
                                    pass
                        elif isinstance(event, BaseAgentEvent):
                            pass
                else:
                    await Console(team.run_stream(task=task_description))
            except asyncio.CancelledError:
                if message_handler:
                    message_handler.handle_agent_message("SYSTEM", "--- Task cancelled ---")
                break
            except Exception as e:
                error_msg = f"An error occurred during the agent run: {e}"
                if message_handler:
                    message_handler.handle_error(error_msg)
                else:
                    print(error_msg)
            finally:
                elapsed_time = time.time() - start_time_url
                url_timings[url] = elapsed_time
                if message_handler:
                    message_handler.handle_agent_message(
                        "SYSTEM",
                        f"[Time] Test completed in {int(elapsed_time)} seconds\n" +
                        f"[State] Promising endpoints: {len(pentest_state.promising_endpoints)}\n" +
                        f"[State] Confirmed vulnerabilities: {len(pentest_state.confirmed_vulns)}"
                    )

        # Print total execution summary
        total_time = time.time() - start_time_total
        summary_msg = (
            f"=== Execution Summary ===\n"
            f"Total execution time: {int(total_time)} seconds\n"
            f"Endpoints tested: {len(pentest_state.tested_endpoints)}\n"
            f"Promising endpoints: {len(pentest_state.promising_endpoints)}\n"
            f"Confirmed vulnerabilities: {len(pentest_state.confirmed_vulns)}"
        )
        if message_handler:
            message_handler.handle_agent_message("SYSTEM", summary_msg)
        else:
            print(summary_msg)

        # Persist state & cleanup
        try:
            save_state(pentest_state.to_dict())
        except Exception:
            pass
    finally:
        # Signal cleanup
        if message_handler and isinstance(message_handler, ImageEnabledMessageHandler):
            message_handler.cleanup()

def handle_keyboard_interrupt(signum, frame):
    """Handle keyboard interrupt gracefully"""
    print("\n\nKeyboard interrupt received. Cleaning up and exiting...")
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_keyboard_interrupt)
    signal.signal(signal.SIGTERM, handle_keyboard_interrupt)

    async def main_async_runner():
        try:
            target_urls, model_name, enabled_tools, context_window_size, obj = get_user_inputs()
            selected_tools = [TOOL_NAME_MAP[name] for name in enabled_tools]
            await run_pentest_team(
                target_urls,
                planner_model=model_name,
                web_model=model_name,
                tool_names=enabled_tools,
                context_window_size=context_window_size,
                objective=obj,
            )
        except KeyboardInterrupt:
            print("\n\nKeyboard interrupt received. Cleaning up and exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"\nAn error occurred: {e}")
            sys.exit(1)

    try:
        asyncio.run(main_async_runner())
    except KeyboardInterrupt:
        print("\n\nKeyboard interrupt received. Cleaning up and exiting...")
        sys.exit(0)

# ----------------- persistent findings log -----------------
def log_finding(url: str, param: str, payload: str, evidence: str):
    try:
        with open("findings.txt", "a", encoding="utf-8") as f:
            f.write(f"{url}|{param}|{payload}|{evidence}\n")
    except Exception:
        pass

def load_sqli_knowledge():
    """Utility to read SQLi guide from disk. Used by other modules."""
    try:
        with open("sql_injection_docs/sqliguide.txt", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"[Error loading SQLi knowledge base: {e}]"

def summarize_knockpy_output(out_dir: str) -> str:
    """Summarise KnockPy output directory. (Function kept for other scripts)."""
    summary = []
    try:
        json_files = [f for f in os.listdir(out_dir) if f.endswith('.json')]
        if json_files:
            for jf in json_files:
                with open(os.path.join(out_dir, jf), 'r', encoding='utf-8') as f:
                    data = f.read()
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

summarize_knockpy_tool = FunctionTool(summarize_knockpy_output, description="Summarize KnockPy output (compressed)")

# ----------------- Payload tracking -----------------

class PayloadTracker:
    """Keeps record of all payloads tested and their outcome so planners
    can avoid duplicates and build on successful injections."""

    def __init__(self):
        self.success: list[tuple[str, str, str]] = []  # (endpoint, payload, note)
        self.fail: list[tuple[str, str]] = []          # (endpoint, payload)

    def record(self, endpoint: str, payload: str, ok: bool, note: str = "") -> None:
        if ok:
            self.success.append((endpoint, payload, note[:120]))
        else:
            self.fail.append((endpoint, payload))

    def summary(self) -> str:
        lines: list[str] = []
        if self.success:
            lines.append("=== SUCCESSFUL PAYLOADS ===")
            for ep, pl, note in self.success[-10:]:
                lines.append(f"✔ {pl.strip()} -> {ep} | {note}")
        if self.fail:
            lines.append(f"Failed payloads tried: {len(self.fail)} (use new variants)")
        return "\n".join(lines) if lines else "No payloads tested yet."

# Global tracker instance (one per run)
payload_tracker = PayloadTracker()

# Expose tracker summary to agents
payload_tracker_summary_tool = FunctionTool(lambda: payload_tracker.summary(),
                                            name="payload_tracker_summary_tool",
                                            description="Return summary of SQLi payloads that have been tested and their outcomes to avoid repeats.")