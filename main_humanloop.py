"""main_humanloop.py – A drop-in alternative to *main.py* that keeps the
original three-agent architecture **and** adds a fourth agent representing a
human operator.  When Planner Beta needs manual interaction in Burp (e.g.
pressing *Send* in Repeater or starting an Intruder attack) it can hand over to
this human-in-the-loop agent, following the pattern shown in
https://microsoft.github.io/autogen/stable//user-guide/agentchat-user-guide/tutorial/human-in-the-loop.html.

Nothing in the original logic is removed: all Burp MCP tools, wrappers and
response summarisers stay intact.  We merely extend the team so the human can
be prompted for actions that can't be automated through MCP (such as clicking
buttons).

Usage:
    python main_humanloop.py
The CLI prompts are exactly the same as *main.py*.
"""
from __future__ import annotations

import asyncio
import signal
import sys
from typing import List

# Re-use everything from the original script.
import main as core

from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.teams import SelectorGroupChat
from autogen_agentchat.ui import Console

# -------------------------------------------------------------
# Helper: build a UserProxyAgent that simply uses input() / print()
# -------------------------------------------------------------

def make_user_proxy() -> UserProxyAgent:  # noqa: D401
    """Return a UserProxyAgent for Burp Suite manual operations."""
    
    # Create a custom UserProxyAgent that overrides the get_human_input method
    class BurpUserProxy(UserProxyAgent):
        def get_human_input(self, prompt: str) -> str:
            # Enhanced prompt for Burp Suite operations
            print("\n" + "="*60)
            print("    BURP SUITE MANUAL OPERATION REQUIRED")
            print("="*60)
            print(prompt)
            print("\n" + "-"*60)
            print("INSTRUCTIONS:")
            print("1. Open Burp Suite and navigate to the appropriate tab")
            print("2. If Repeater: paste request and click 'Send'")
            print("3. If Intruder: configure payloads (use JSON array format) and start attack")
            print("4. **CRITICAL**: After execution, LEAVE THE RESPONSE VISIBLE in active editor")
            print("5. Report completion: AI will use get_active_editor_contents to read actual response")
            print("6. The AI needs to see the focused JTextArea in Burp to get the real data")
            print("-"*60)
            print("\nReporting format:")
            print("'COMPLETED: [Repeater/Intruder] operation finished, response visible in editor'")
            print("-"*60)
            return input("\nYour response: ")
    
    return BurpUserProxy(name="HumanOperator")


# -------------------------------------------------------------
# run_pentest_team_humanloop – copy of core.run_pentest_team with a proxy
# -------------------------------------------------------------

async def run_pentest_team_humanloop(
    target_urls: List[str],
    planner_model: str = "gpt-4.1-mini",
    web_model: str = "gpt-4.1-mini",
    tool_names: List[str] | None = None,
    context_window_size: int = 8,
    objective: str = "Gain admin access via SQL injection.",
):
    """Invokes the original planners + WebPenTester + HumanOperator."""

    # First, create the original three agents by calling a *trimmed* version of
    # core.run_pentest_team up until the point where it builds the team.  That
    # function is too large to reuse piecemeal, so we replicate the critical
    # constructions here while importing all helper utilities directly from
    # *core* to avoid code duplication.

    # -------------- STEP 1: model clients ------------------
    planner_client = core.get_model_client(planner_model)
    web_client = core.get_model_client(web_model)

    # -------------- STEP 2: tool selection -----------------
    if tool_names:
        selected_tools = [core.TOOL_NAME_MAP[n] for n in tool_names if n in core.TOOL_NAME_MAP]
    else:
        selected_tools = list(core.TOOL_NAME_MAP.values())

    # Partition tools as original
    advanced_names = {"sqlmap_tool", "wapiti_tool", "read_wapiti_report_tool", "ffuf_tool"}
    alpha_tools = [t for t in selected_tools if t.name not in advanced_names]
    beta_tools_extra = [t for t in selected_tools if t.name in advanced_names]

    # Fetch Burp MCP tools (simplified wrapping for humanloop)
    burp_server_params = core.SseServerParams(url="http://127.0.0.1:9876/sse", headers={})
    cache_key = burp_server_params.url
    if cache_key not in core._BURP_TOOLS_CACHE:
        core._BURP_TOOLS_CACHE[cache_key] = await core.mcp_server_tools(burp_server_params)
    burp_tools = core._BURP_TOOLS_CACHE[cache_key]
    
    # Simple wrapper for humanloop - just apply basic trimming without complex path logic
    def _simple_trim_tool(tool):
        """Simple version of tool wrapper for humanloop compatibility."""
        import inspect
        from autogen_core.tools import FunctionTool
        
        def _wrapper(*args, **kwargs):
            result = tool(*args, **kwargs)
            if inspect.iscoroutine(result):
                async def _async_wrapper():
                    raw = await result
                    # Basic trimming for humanloop
                    if isinstance(raw, str) and len(raw) > 2000:
                        return raw[:2000] + "...[truncated for readability]"
                    return raw
                return _async_wrapper()
            else:
                # Basic trimming for sync results
                if isinstance(result, str) and len(result) > 2000:
                    return result[:2000] + "...[truncated for readability]"
                return result
        
        return FunctionTool(_wrapper, name=tool.name, description=(tool.description or "") + " (trimmed)")
    
    wrapped_burp_tools = []
    for t in burp_tools:
        if t.name and ("send_http" in t.name or t.name.endswith("send_to_intruder") or t.name.endswith("create_repeater_tab")):
            try:
                wrapped_burp_tools.append(_simple_trim_tool(t))
            except Exception:
                wrapped_burp_tools.append(t)
        else:
            wrapped_burp_tools.append(t)

    # Create properly typed placeholder tools
    # Assemble final tool lists (placeholders removed)
    planner_beta_tools = wrapped_burp_tools + beta_tools_extra
    planner_alpha_tools = alpha_tools

    # -------------- STEP 3: build agents -------------------
    bounded_ctx = core.BufferedChatCompletionContext(buffer_size=context_window_size)

    planner_alpha = AssistantAgent(
        name="PlannerAlpha",
        model_client=planner_client,
        system_message=(
            "You are PlannerAlpha, the reconnaissance lead.  Your duties:\n"
            "1. Map the target within scope using curl_headers_tool, arjun_tool, etc.\n"
            "2. Locate login/auth forms and enumerate parameter names.\n"
            "3. NEVER attempt SQL-injection payloads yourself.\n"
            "4. When a promising endpoint is found, craft a concise hand-over message to PlannerBeta containing:\n"
            "   • full URL (no shortened paths)\n   • HTTP method\n   • all parameters with example benign values\n   • any hidden fields (e.g., debug)\n"
            "5. Optionally propose classic SQLi payloads via bypasspayloads_tool."
        ),
        model_context=bounded_ctx,
        tools=planner_alpha_tools,
    )

    planner_beta = AssistantAgent(
        name="PlannerBeta",
        model_client=planner_client,
        system_message=(
            "You are PlannerBeta, the Burp Suite exploitation specialist. Your PRIMARY METHOD: create Repeater tabs and Intruder attacks for manual execution.\n\n"
            "=== MANDATORY TOOL USAGE ===\n"
            "1. **FIRST**: Always establish baseline with create_repeater_tab (clean request)\n"
            "2. **SECOND**: Create payload testing with send_to_intruder (JSON payload array)\n"
            "3. **DELEGATE**: Hand over to HumanOperator for manual execution\n"
            "4. **ANALYZE**: Use get_active_editor_contents to read actual Burp responses\n\n"
            "=== TOOL CALL EXAMPLES ===\n"
            "```\n"
            "# Step 1: Create baseline Repeater tab\n"
            "create_repeater_tab(\n"
            "    content=\"POST /login.php HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nUser-Agent: Mozilla/5.0\\r\\nConnection: close\\r\\n\\r\\nusername=admin&password=test\",\n"
            "    targetHostname=\"target.com\",\n"
            "    targetPort=443,\n"
            "    usesHttps=True,\n"
            "    tabName=\"Baseline Login Test\"\n"
            ")\n\n"
            "# Step 2: Create Intruder attack with payloads\n"
            "send_to_intruder(\n"
            "    content=\"POST /login.php HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nUser-Agent: Mozilla/5.0\\r\\nConnection: close\\r\\n\\r\\nusername=§admin§&password=test\",\n"
            "    targetHostname=\"target.com\",\n"
            "    targetPort=443,\n"
            "    usesHttps=True,\n"
            "    tabName=\"SQLi Username Attack\",\n"
            "    payloads=[\"admin' OR '1'='1'--\", \"admin' OR 1=1#\", \"' OR 'x'='x\"]\n"
            ")\n"
            "```\n\n"
            "=== AFTER HUMAN EXECUTION ===\n"
            "When HumanOperator reports completion:\n"
            "1. **IMMEDIATELY** call get_active_editor_contents\n"
            "2. Parse the actual HTTP response from Burp's focused editor\n"
            "3. Look for: status changes, length differences, SQL errors, success indicators\n"
            "4. Compare against baseline response for anomalies\n"
            "5. Make exploitation decisions based on REAL data, not human descriptions\n\n"
            "=== PAYLOAD PREPARATION ===\n"
            "Use bypasspayloads_tool with format_type='json' to get ready-to-use payload arrays:\n"
            "```\n"
            "payloads = bypasspayloads_tool(count=5, format_type='json')\n"
            "# Then provide these to HumanOperator for Intruder configuration\n"
            "```\n\n"
            "**CRITICAL**: You MUST actually call create_repeater_tab and send_to_intruder tools before asking human to do anything!"
        ),
        model_context=bounded_ctx,
        tools=planner_beta_tools,
    )

    web_pentester_agent = core.MultimodalWebSurfer(
        name="WebPenTester",
        model_client=web_client,
        start_page=target_urls[0] if target_urls else None,
        headless=False,
        use_ocr=True,
    )

    human_proxy = make_user_proxy()

    # -------------- STEP 4: build team ---------------------
    selector_prompt = (
        "Select the next agent for human-guided Burp Suite penetration testing:\n\n"
        "=== SELECTION PRIORITY ===\n"
        "1. After PlannerAlpha reconnaissance → PlannerBeta (for Burp Suite setup)\n"
        "2. After PlannerBeta creates Repeater/Intruder → HumanOperator (for manual execution)\n"
        "3. After HumanOperator reports completion → PlannerBeta (MUST call get_active_editor_contents!)\n"
        "4. WebPenTester only when both planners agree on browser verification\n\n"
        "=== CRITICAL MCP WORKFLOW ===\n"
        "• **MANDATORY**: After human completes Burp operations, PlannerBeta MUST call get_active_editor_contents\n"
        "• This function reads the currently focused response in Burp's active editor (like focused JTextArea)\n"
        "• PlannerBeta analyzes REAL HTTP response data from Burp, not human descriptions\n"
        "• Only after reading actual response data should PlannerBeta make next decisions\n\n"
        "=== BURP SUITE INTEGRATION ===\n"
        "• Prioritize Repeater tab creation over direct HTTP requests\n"
        "• Emphasize Intruder attacks with JSON-formatted payload arrays\n"
        "• Always delegate manual button pressing to HumanOperator\n"
        "• Human leaves response visible → PlannerBeta reads it via MCP → Analysis based on real data\n"
        "• Ensure complete request/payload information is provided as structured data"
    )

    termination = TextMentionTermination("TERMINATE") | MaxMessageTermination(max_messages=205)

    team = SelectorGroupChat(
        [planner_alpha, planner_beta, web_pentester_agent, human_proxy],
        model_client=planner_client,
        selector_prompt=selector_prompt,
        termination_condition=termination,
        allow_repeated_speaker=False,
    )

    # -------------- STEP 5: run per-target -----------------
    for url in target_urls:
        task = f"Pentest {url}. Objective: {objective}"
        await Console(team.run_stream(task=task))


# -------------------------------------------------------------
# CLI entry-point (mirrors main.py)
# -------------------------------------------------------------

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    try:
        urls, model, enabled_tools, ctx_size, obj = core.get_user_inputs()
        asyncio.run(
            run_pentest_team_humanloop(
                urls,
                planner_model=model,
                web_model=model,
                tool_names=enabled_tools,
                context_window_size=ctx_size,
                objective=obj,
            )
        )
    except KeyboardInterrupt:
        print("\nInterrupted – exiting.") 