import asyncio
import os
import time
from dotenv import load_dotenv
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_ext.tools.mcp import SseServerParams, mcp_server_tools
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_agentchat.ui import Console
from autogen_agentchat.conditions import TextMessageTermination
from typing import List
# Load environment variables
load_dotenv()

async def create_burp_tools():
    """Create a list of Burp Suite MCP tools using the SSE server."""
    # Configure the Burp MCP server connection
    server_params = SseServerParams(
        url="http://127.0.0.1:9876/sse",
        headers={}  # No authentication required
    )
    
    # Get all available tools from the MCP server
    return await mcp_server_tools(server_params)

# Define helper functions for token counting
def _sum_models_usage(messages: List):
    total = 0
    for msg in messages:
        usage = getattr(msg, "models_usage", None)
        if usage:
            total += getattr(usage, "prompt_tokens", 0) + getattr(usage, "completion_tokens", 0)
    return total

def _approx_tokens(messages: List):
    total_chars = sum(len(getattr(m, "content", "")) for m in messages)
    return int(total_chars / 4)  # crude 4-char per token heuristic

async def main():
    # Initialize the model client
    model_client = OpenAIChatCompletionClient(
        model="gpt-4o-mini",
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    # Create tools
    tools = await create_burp_tools()
    
    # Create the primary agent with all tools
    primary_agent = AssistantAgent(
        name="security_analyst",
        model_client=model_client,
        tools=tools,
        system_message="""You are a security analyst agent. Your goal: discover SQL injection in the target.
PRIORITY: Locate HTML forms first and test their input fields for SQLi before any URL parameter manipulation.
STEPS:
A. Recon: enumerate site pages, **scrape forms**, collect action URLs + field names.
B. Viability check: for each form field, decide if SQLi attempts are meaningful; skip static pages/links.
C. Exploit: attempt SQLi only on viable form fields; then test URL parameters if needed.
D. Record: page|form|field|status|evidence|next (one line each).
RULES:
- Use Burp tools for form discovery (crawler, param miner) first.
- If waiting on BurpSuite results, say nothing.
- No greetings/thanks. Be brief. Never give up until done.""",
        reflect_on_tool_use=True  # Enable reflections for more insight
    )
    
    # Create a critic agent to evaluate the results
    critic_agent = AssistantAgent(
        name="security_critic",
        model_client=model_client,
        system_message="""You are a critic agent. Your task is to:
1. Evaluate the analyst's findings.
2. Point out omissions or next actions in bullet form.
3. Suggest additional tools or adjustments.
Be succint and to the point.
4. Respond with 'TERMINATE' only when the analysis is exhaustive.
5. No greetings, no thanks, no pleasantries. Stay concise. Never tell the team to give up.""",
        reflect_on_tool_use=True
    )
    
    # Create a team with both agents
    team = RoundRobinGroupChat(
        [primary_agent, critic_agent],
        termination_condition=TextMessageTermination("TERMINATE") # Allow up to 10 rounds of interaction
    )
    
    # Define the target URL
    target_url = "https://jupiter.challenges.picoctf.org/problem/53751/"
    
    # Timing start
    start_time = time.time()

    # Run the security analysis task with live streaming so you can see what the team is doing and thinking.
    result = await Console(
        team.run_stream(
            task=f"""Target: {target_url}
Objective: find SQL injection.
1. Crawl site and enumerate **forms** and their fields first.
2. Test those fields for SQLi viability.
3. Only after exhausting forms, test URL parameters if still needed.
4. Summarize concise findings in bullets.
Begin."""
        )
    )

    # Timing end
    elapsed = time.time() - start_time

    # Token counting
    token_count = _sum_models_usage(result.messages)
    if token_count == 0:
        token_count = _approx_tokens(result.messages)

    # Print the results with stats
    print("\n=== Security Analysis Results ===")
    print(result)
    print(f"\nTotal time: {elapsed:.2f} seconds")
    print(f"Approx. tokens used: {token_count}")

if __name__ == "__main__":
    asyncio.run(main()) 