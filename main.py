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
from state_tracking import PenTestState, SQLiTestState
from state_persistence import load_state, save_state
from test_sequences import TestManager
from hashlib import md5
from urllib.parse import urlparse

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

# All other tools are disabled for now, only RAG is available to the planner.
# Import all tool functions
from tools import (
    run_curl_headers, run_sqlmap, arjun_scan, pysslscan_scan,
    aquatone_scan, summarize_aquatone_output,
    knockpy_scan, summarize_knockpy_output,
    run_ffuf, run_wapiti, read_wapiti_report,
    save_image_to_temp, google_custom_search, search_security_sites
)

# Attempt to import Gemini client; if unavailable, fall back to OpenAI (same interface)
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
    print("2. gpt-4.1-mini")
    print("3. gpt-4o-mini")
    print("4. gpt-4.1-nano")
    print("5. gemini-2.0-flash")
    
    model_choice = input("Please enter your choice (1-5): ").strip()
    model_map = {
        "1": "o3-mini",
        "2": "gpt-4.1-mini",
        "3": "gpt-4o-mini",
        "4": "gpt-4.1-nano",
        "5": "gemini-2.0-flash"
    }
    
    model_name = model_map.get(model_choice, "o3-mini")
    
    print("\nEnter one or more target URLs to test for SQL injection (comma-separated):")
    urls = input("Target URLs: ").strip()
    while not urls:
        urls = input("Target URLs cannot be empty. Please enter at least one URL: ").strip()
    url_list = [u.strip() for u in urls.split(",") if u.strip()]

    print("\nAdvanced Tools Configuration:")
    print("The following tools require additional setup and may take longer to run:")
    print("1. SQLMap (SQL injection testing)")
    print("2. Wapiti (Web vulnerability scanner)")
    print("3. Aquatone (Visual reconnaissance)")
    
    tool_choice = input("\nWould you like to enable these advanced tools? (y/n): ").strip().lower()
    enabled_tools = list(TOOL_NAME_MAP.keys())
    
    if tool_choice != 'y':
        # Remove advanced and high-token tools if not enabled
        disabled_tools = [
            'sqlmap_tool', 'wapiti_tool', 'read_wapiti_report_tool', 
            'aquatone_tool', 'summarize_aquatone_tool',
            'google_search_tool', 'security_sites_search_tool', 'query_rag_function_tool'
        ]
        enabled_tools = [tool for tool in enabled_tools if tool not in disabled_tools]
    
    return url_list, model_name, enabled_tools

# Create enhanced FunctionTools with improved descriptions
curl_headers_tool = FunctionTool(run_curl_headers, description="Run curl to get HTTP headers and basic server information. Use for initial reconnaissance.")
sqlmap_tool = FunctionTool(run_sqlmap, description="Run advanced SQLMap scan with level 2 risk 2 for SQL injection detection. Returns structured vulnerability report.")
arjun_tool = FunctionTool(arjun_scan, description="Discover hidden HTTP parameters using Arjun. Essential for finding injection points.")
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
text_mention_termination = TextMentionTermination("TERMINATE")
max_messages_termination = MaxMessageTermination(max_messages=205)
termination = text_mention_termination | max_messages_termination
def load_sqli_knowledge():
    try:
        with open("sql_injection_docs/sqliguide.txt", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return "[Error loading SQLi knowledge base: {}]".format(e)

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
}

# Remove tools overlapped by BurpSuite MCP (active scan & SQLi testing)
REMOVED_TOOLS = {"sqlmap_tool", "wapiti_tool", "read_wapiti_report_tool"}
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

# --------------------------------------------------
# Helper to obtain the correct model client based on model name prefix
# --------------------------------------------------

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

        # --- Load SQLi knowledge base ---
        sqli_knowledge = load_sqli_knowledge()

        # --- Lightweight guide compression to save tokens ---
        def _compress_guide(text: str, max_lines: int = 120) -> str:
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
        fundamental_memory = ListMemory()
        # Load SQLi guide (if present)
        if sqli_knowledge and not sqli_knowledge.startswith("[Error"):
            await fundamental_memory.add(
                MemoryContent(content=_compress_guide(sqli_knowledge), mime_type=MemoryMimeType.TEXT)
            )

        # Load Burp MCP exploitation playbook from config if available
        burp_playbook = config.get("BURP_MCP_INJECTION_GUIDE")
        if burp_playbook:
            await fundamental_memory.add(
                MemoryContent(content=_compress_guide(burp_playbook), mime_type=MemoryMimeType.TEXT)
            )

        # Add state tracking to memory
        await fundamental_memory.add(
            MemoryContent(
                content=f"Current Phase: {pentest_state.current_phase}\n" +
                        f"Tested Endpoints: {len(pentest_state.tested_endpoints)}\n" +
                        f"Promising Endpoints: {len(pentest_state.promising_endpoints)}\n" +
                        f"Confirmed Vulnerabilities: {len(pentest_state.confirmed_vulns)}",
                mime_type=MemoryMimeType.TEXT
            )
        )

        # --- Fetch Burp Suite MCP tools (PlannerBeta only) ---
        burp_server_params = SseServerParams(url="http://127.0.0.1:9876/sse", headers={})
        burp_tools = await mcp_server_tools(burp_server_params)

        # --- Partition tools ---
        advanced_names = {"sqlmap_tool", "wapiti_tool", "read_wapiti_report_tool"}
        alpha_tools = [t for t in selected_tools if t.name not in advanced_names]
        beta_tools_extra = [t for t in selected_tools if t.name in advanced_names]
        
        # Combine for beta: burp + advanced
        planner_beta_tools = burp_tools + beta_tools_extra
        
        # PlannerAlpha remains same but without advanced
        planner_alpha_tools = alpha_tools

        # --- Define the Debating Planner Agents ---
        # ---------------- Prompt triplet ----------------
        PERSISTENCE_REM = (
            "You are an autonomous agent — continue until the task is fully solved; never yield early."
        )
        TOOL_REM = (
            "If unsure about page content, DOM structure, or Burp data, call an appropriate TOOL instead of guessing."
        )
        PLAN_REM = (
            "Plan briefly before each tool call, and reflect on results before deciding next action."
        )
        allowed_hosts = {urlparse(u).netloc for u in target_urls}
        host_reminder = (
            "\nALLOWED_HOSTS: " + ", ".join(sorted(allowed_hosts)) +
            "\nAlways use one of these exact hosts in any manual HTTP request or Burp action. "
            "Never invent or shorten domain names."
        )

        no_idle_rule = "If you did not call any tool in your previous turn, you MUST call an appropriate tool now; otherwise reply with an empty string."
        planner_sys_msg = (
            planner_prompt_override or short_planner_sys_msg or planner_system_message
        ) + "\n" + PERSISTENCE_REM + "\n" + TOOL_REM + "\n" + PLAN_REM + "\n" + no_idle_rule + host_reminder
        bounded_ctx = BufferedChatCompletionContext(buffer_size=4)
        planner_alpha = AssistantAgent(
            name="PlannerAlpha",
            model_client=planner_client,
            system_message=planner_sys_msg,
            model_context=bounded_ctx,
            tools=planner_alpha_tools,
            memory=[fundamental_memory],
            reflect_on_tool_use=True,
        )

        planner_beta_msg = (
            planner_sys_msg
            + "\n\nYou are PlannerBeta. You control BurpSuite MCP tools and advanced exploitation tools. "
            + "If selected twice consecutively you must return an empty string."
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
        webpentester_rules_text = " ".join(webpentester_rules)
        webpentester_sys_msg = (
            "You control a real browser. "
            "Act ONLY when explicitly instructed by planners. "
            "After each action, respond with a single short line (<=25 words) describing exactly what you observed, prefixed with 'RESULT:'. "
            + webpentester_rules_text
        )

        web_pentester_agent = MultimodalWebSurfer(
            name="WebPenTester",
            model_client=web_client,
            start_page=target_urls[0] if target_urls else None,
            headless=False,
            use_ocr=True,

        )

        # --- Team Selector Prompt ---
        selector_prompt_final = selector_prompt_override or selector_prompt

        # --- Team (with two planners and one web surfer) ---
        team = SelectorGroupChat(
            [planner_alpha, planner_beta, web_pentester_agent],
            model_client=planner_client,
            termination_condition=termination,
            selector_prompt=selector_prompt_final + "\nRule 6: Never select WebPenTester unless the last two messages came from different planners who agreed on a single action.",
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
            
            if message_handler:
                message_handler.handle_agent_message("SYSTEM", f"\n[Target] {url}\n[Time] Starting test...")
            else:
                print(f"\n[Target] {url}")

            task_description = (
                f"Pentest {url}. PRIMARY OBJECTIVE: find the login page (or any credential form) *inside* the supplied base URL and its sub-paths, then test it for SQL injection.\n"
                "MANDATORY FIRST ACTION: load the root page, read the HTML, extract links/forms containing keywords like login, signin, auth, account, user, register. Stay on same domain & sub-path.\n"
                "After locating the login form: enumerate its fields, craft SQLi payloads, and use BurpSuite MCP (burp_crawl ➜ burp_sqli_scan) to probe. Do NOT wander to parent paths or other hosts.\n"
                f"Current phase: {pentest_state.current_phase}. Promising={len(pentest_state.promising_endpoints)} Confirmed={len(pentest_state.confirmed_vulns)}.\n"
                "Replies ≤120 words; statement style."
            )

            try:
                if message_handler:
                    stream = team.run_stream(task=task_description)
                    async for event in stream:
                        if cancel_event and cancel_event.is_set():
                            await stream.aclose()
                            break
                        if isinstance(event, BaseChatMessage):
                            message_handler.handle_agent_message(event.source, event.content)
                            
                            # Update state based on message content
                            if "SQL" in event.content or "query" in event.content.lower():
                                current_endpoint = pentest_state.current_target
                                if current_endpoint not in pentest_state.promising_endpoints:
                                    pentest_state.promising_endpoints.append(current_endpoint)
                                    
                            if "success" in event.content.lower() or "vulnerable" in event.content.lower():
                                current_endpoint = pentest_state.current_target
                                if current_endpoint not in pentest_state.confirmed_vulns:
                                    pentest_state.confirmed_vulns.append(current_endpoint)
                                    # simplistic log; param/payload placeholders
                                    log_finding(current_endpoint, "username", "payload", "vulnerable")
                                    
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
            target_urls, model_name, enabled_tools = get_user_inputs()
            selected_tools = [TOOL_NAME_MAP[name] for name in enabled_tools]
            await run_pentest_team(target_urls, planner_model=model_name, web_model=model_name, tool_names=enabled_tools)
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