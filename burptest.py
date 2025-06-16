import asyncio
import sys
import time
import aiofiles

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_agentchat.teams import SelectorGroupChat
from autogen_core.memory import ListMemory, MemoryContent, MemoryMimeType
from autogen_core.model_context import BufferedChatCompletionContext
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.messages import BaseChatMessage

from autogen_ext.tools.mcp import SseServerParams, mcp_server_tools

# Re-use utilities, config and tools from main.py
from main import (
    config,
    get_model_client,
    load_sqli_knowledge,
    TOOL_NAME_MAP,
)


# ----------------------------
# Helper to build planner agents (async)
# ----------------------------

async def build_planners(target_urls):
    """Return PlannerAlpha and PlannerBeta agents without any WebSurfer."""
    # --- Shared memory (high-level knowledge) ---
    fundamental_memory = ListMemory()

    sqli_knowledge = load_sqli_knowledge()
    if sqli_knowledge and not sqli_knowledge.startswith("[Error"):
        await fundamental_memory.add(
            MemoryContent(content=sqli_knowledge, mime_type=MemoryMimeType.TEXT)
        )

    burp_playbook = config.get("BURP_MCP_INJECTION_GUIDE")
    if burp_playbook:
        await fundamental_memory.add(
            MemoryContent(content=burp_playbook, mime_type=MemoryMimeType.TEXT)
        )

    # Add explicit scope reminder to memory
    await fundamental_memory.add(
        MemoryContent(
            content="ALLOWED_SCOPE: " + ", ".join(target_urls) + "\nReject any request outside these prefixes.",
            mime_type=MemoryMimeType.TEXT,
        )
    )

    # Fetch Burp MCP tools for PlannerBeta
    burp_server_params = SseServerParams(url="http://127.0.0.1:9876/sse", headers={})
    burp_tools = await mcp_server_tools(burp_server_params)

    # Both planners will use only BurpSuite MCP tools
    planner_alpha_tools = burp_tools
    planner_beta_tools = burp_tools

    # System messages
    path_rule = f"ALLOWED_PATH_PREFIX = {' '.join([url.split('://')[1] for url in target_urls])}. Never send HTTP requests to '/' or other paths outside these prefixes."
    planner_sys_msg = config.get("SHORT_PLANNER_SYSTEM_MESSAGE", "You are Planner.") + "\n" + path_rule

    bounded_ctx = BufferedChatCompletionContext(buffer_size=6)

    planner_model = get_model_client("gpt-4o-mini")

    planner_alpha = AssistantAgent(
        name="PlannerAlpha",
        model_client=planner_model,
        system_message=planner_sys_msg,
        model_context=bounded_ctx,
        tools=planner_alpha_tools,
        memory=[fundamental_memory],
    )

    planner_beta_msg = planner_sys_msg + "\n\nYou are PlannerBeta. You control BurpSuite MCP tools and advanced exploitation tools. If selected twice consecutively you must return an empty string."

    planner_beta = AssistantAgent(
        name="PlannerBeta",
        model_client=planner_model,
        system_message=planner_beta_msg,
        model_context=bounded_ctx,
        tools=planner_beta_tools,
        memory=[fundamental_memory],
    )

    return planner_alpha, planner_beta


async def run_burp_only(target_urls):
    """Run two-planner team (no WebSurfer) focusing on BurpSuite."""
    if not target_urls:
        raise ValueError("Provide at least one target URL.")

    planner_alpha, planner_beta = await build_planners(target_urls)

    # Termination after 150 messages or explicit TERMINATE mention
    termination = TextMentionTermination("TERMINATE") | MaxMessageTermination(max_messages=150)

    selector_prompt = "[BURP-ONLY MODE] Alternate between planners until task complete. WebSurfer is not available."

    team = SelectorGroupChat(
        [planner_alpha, planner_beta],
        model_client=get_model_client("gpt-4o-mini"),
        selector_prompt=selector_prompt,
        termination_condition=termination,
        allow_repeated_speaker=True,
    )

    task_description = (
        "Pentest target(s): " + ", ".join(target_urls) + ". Focus exclusively on BurpSuite MCP tools. "
        "No browser actions available. Produce concise, actionable steps."
    )

    start = time.time()
    print("[+] Starting Burp-only planners…")

    log_path = "burp_convo_log.txt"
    # Truncate previous log
    async with aiofiles.open(log_path, "w") as _f:
        pass

    stream = team.run_stream(task=task_description)
    async with aiofiles.open(log_path, "a", encoding="utf-8") as log_f:
        async for event in stream:
            if isinstance(event, BaseChatMessage):
                role = event.source
                content = event.content.strip()
                await log_f.write(f"{role}: {content}\n\n")
                print(f"[{role}] {content}")

    print(f"[+] Completed in {int(time.time()-start)}s. Log saved to {log_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python burp_only_test.py <url1> [url2 …]")
        sys.exit(1)
    asyncio.run(run_burp_only(sys.argv[1:])) 