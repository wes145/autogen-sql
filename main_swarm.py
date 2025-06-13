import sys
import asyncio
import subprocess
import signal
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import Swarm
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
tool_usage_guidelines = config['TOOL_USAGE_GUIDELINES']
communication_rules = config['COMMUNICATION_RULES']
webpentester_rules = config['WEBPENTESTER_RULES']
planner_strategies = config['PLANNER_STRATEGIES']

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
    print("=== Interactive SQLi Pentest CLI Tool (Swarm Mode) ===")
    print("Choose AI model:")
    print("1. gpt-4o-mini (Recommended)")
    print("2. gpt-4.1-nano")
    print("3. gpt-4.1-mini")
    print("4. gpt-o3-mini")
    print("5. gemini-2.0-flash")
    
    model_choice = input("Please enter your choice (1-5): ").strip()
    model_map = {
        "1": "gpt-4o-mini",
        "2": "gpt-4.1-nano",
        "3": "gpt-4.1-mini",
        "4": "gpt-o3-mini",
        "5": "gemini-2.0-flash"
    }
    
    model_name = model_map.get(model_choice, "gpt-4o-mini")
    
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
        # Remove advanced tools if not enabled
        disabled_tools = ['sqlmap_tool', 'wapiti_tool', 'read_wapiti_report_tool', 
                         'aquatone_tool', 'summarize_aquatone_tool']
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
}

def get_model_client(model_name: str):
    return OpenAIChatCompletionClient(model=model_name)

async def run_pentest_team(
    target_urls: list[str],
    message_handler=None,
    cancel_event=None,
    # Model customisation
    planner_model: str = "gpt-4o-mini",
    web_model: str = "gpt-4o-mini",
    # Prompt overrides
    planner_prompt_override: str | None = None,
    # Tool selection
    tool_names: list[str] | None = None,
):
    """Run the pentest team using a Swarm approach with specialized agents."""
    if message_handler:
        message_handler = ImageEnabledMessageHandler(message_handler)

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

        # Step 1: Set up agent memory (simple dict for now)
        agent_memory = {"success": [], "fail": []}

        # Step 2: Set up model clients for each agent
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

        # --- Define the Swarm Agents ---
        planner_sys_msg = planner_prompt_override or planner_system_message
        
        # Create specialized planners with handoff capabilities
        recon_planner = AssistantAgent(
            name="ReconPlanner",
            model_client=planner_client,
            handoffs=["VulnPlanner", "ResearchPlanner", "WebPenTester"],
            system_message=planner_sys_msg + """
            You are a reconnaissance specialist in the penetration testing team.
            Your primary focus is on gathering information about the target.
            You can hand off to:
            - VulnPlanner: When you find potential vulnerabilities
            - ResearchPlanner: When you need deeper analysis of findings
            - WebPenTester: When you need browser-based reconnaissance
            
            Use your tools to:
            1. Gather initial information about the target
            2. Identify potential entry points
            3. Map the application structure
            
            After completing your tasks, hand off to the appropriate agent.
            Use TERMINATE when the overall mission is complete.
            """,
            tools=selected_tools,
        )
        
        vuln_planner = AssistantAgent(
            name="VulnPlanner",
            model_client=planner_client,
            handoffs=["ReconPlanner", "ResearchPlanner", "WebPenTester"],
            system_message=planner_sys_msg + """
            You are a vulnerability assessment specialist in the penetration testing team.
            Your primary focus is on identifying and analyzing security vulnerabilities.
            You can hand off to:
            - ReconPlanner: When you need more information about the target
            - ResearchPlanner: When you need to analyze potential exploits
            - WebPenTester: When you need to test vulnerabilities in the browser
            
            Use your tools to:
            1. Test for SQL injection vulnerabilities
            2. Analyze security misconfigurations
            3. Identify potential attack vectors
            
            After completing your tasks, hand off to the appropriate agent.
            Use TERMINATE when the overall mission is complete.
            """,
            tools=selected_tools,
        )
        
        research_planner = AssistantAgent(
            name="ResearchPlanner",
            model_client=planner_client,
            handoffs=["ReconPlanner", "VulnPlanner", "WebPenTester"],
            system_message=planner_sys_msg + """
            You are a research specialist in the penetration testing team.
            Your primary focus is on analyzing findings and researching solutions.
            You can hand off to:
            - ReconPlanner: When you need more information about the target
            - VulnPlanner: When you find potential vulnerabilities to test
            - WebPenTester: When you need to verify research findings
            
            Use your tools to:
            1. Research known vulnerabilities and exploits
            2. Analyze tool outputs and findings
            3. Develop attack strategies
            
            After completing your tasks, hand off to the appropriate agent.
            Use TERMINATE when the overall mission is complete.
            """,
            tools=selected_tools,
        )

        # --- Web Surfer Agent ---
        web_pentester_agent = MultimodalWebSurfer(
            name="WebPenTester",
            model_client=web_client,
            start_page=target_urls[0] if target_urls else None,
            headless=False,
            use_ocr=True,
            handoffs=["ReconPlanner", "VulnPlanner", "ResearchPlanner"],
            system_message="""
            You are a web penetration testing specialist focused on browser-based actions.
            Your primary role is to execute browser actions and report findings.
            
            You can hand off to:
            - ReconPlanner: When you discover new pages or endpoints
            - VulnPlanner: When you find potential vulnerabilities
            - ResearchPlanner: When you need analysis of browser findings
            
            Your responsibilities:
            1. Execute browser actions (click, type, submit) as instructed
            2. Stay focused on the target site
            3. Report exactly what happens in the browser
            4. Hand off to appropriate planners when you:
               - Complete a requested action
               - Find something interesting
               - Need guidance on next steps
               - Encounter an error or limitation
            
            Never navigate to URLs from tool outputs unless explicitly instructed.
            Use TERMINATE when the overall mission is complete.
            """
        )

        # --- Swarm Team ---
        team = Swarm(
            [recon_planner, vuln_planner, research_planner, web_pentester_agent],
            termination_condition=termination,
        )

        # --- Interactive Loop ---
        url_timings = {}
        if message_handler:
            message_handler.handle_agent_message("SYSTEM", "[Swarm Mode] Starting agent team...")
        else:
            print("\n[Swarm Mode] Starting agent team on user-supplied URLs...")

        for url in target_urls:
            if cancel_event and cancel_event.is_set():
                break
            start_time_url = time.time()
            if message_handler:
                message_handler.handle_agent_message("SYSTEM", f"\n[Target] {url}\n[Time] Starting test...")
            else:
                print(f"\n[Target] {url}")

            task_description = (
                f"Target URL: {url}\n\n"
                f"MISSION: Conduct comprehensive penetration testing focusing on SQL injection and web vulnerabilities.\n\n"
                f"RESPONSE GUIDELINES: Keep responses under 100 words. Summarize tool results concisely.\n\n"
                f"SWARM ROLES:\n"
                f"- ReconPlanner: Focus on initial reconnaissance and information gathering\n"
                f"- VulnPlanner: Focus on vulnerability assessment and exploitation\n"
                f"- ResearchPlanner: Focus on analyzing findings and researching solutions\n"
                f"- WebPenTester: Execute browser actions and report findings\n\n"
                f"COLLABORATION RULES:\n"
                f"- Each agent should focus on their specialty but collaborate with others\n"
                f"- Use handoffs to transfer control to the most appropriate agent\n"
                f"- Share findings and insights with the team\n"
                f"- Coordinate actions to avoid duplicate work\n\n"
                f"HANDOFF GUIDELINES:\n"
                f"- After completing a task, hand off to the most appropriate agent\n"
                f"- When finding something interesting, hand off to the relevant specialist\n"
                f"- When needing guidance, hand off to the appropriate planner\n"
                f"- When encountering errors, hand off to a planner for direction\n\n"
                f"TOOL USAGE:\n"
                f"- Use query_rag_function_tool() for cached attack knowledge\n"
                f"- Use google_search_tool() for current techniques\n"
                f"- Use security_sites_search_tool() for authoritative sources\n\n"
                f"WEBPENTESTER RULES:\n"
                f"- Execute ONLY browser actions (click, type, submit) as instructed\n"
                f"- Stay focused on the target site\n"
                f"- Report exactly what happened in the browser\n"
                f"- If a browser action is impossible, hand off to a planner\n\n"
                f"SUCCESS CRITERIA: Identify and exploit vulnerabilities, particularly SQL injection.\n"
                f"RESEARCH STRATEGY: Use RAG for general knowledge, Google Search for current techniques, Security Sites for authoritative sources."
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
                        f"[Time] Test completed in {int(elapsed_time)} seconds",
                    )

        # Print total execution summary
        total_time = time.time() - start_time_total
        summary_msg = f"=== Execution Summary ===\nTotal execution time: {int(total_time)} seconds"
        if message_handler:
            message_handler.handle_agent_message("SYSTEM", summary_msg)
        else:
            print(summary_msg)
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
            await run_pentest_team(target_urls, planner_model=model_name, tool_names=enabled_tools)
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