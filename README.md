# AutoGen SQL Injection Penetration Testing Framework - Setup Guide

## Overview

This framework provides an AI-driven penetration testing CLI built around AutoGen agents that specialize in SQL injection testing. The system orchestrates three main agents:

- **PlannerAlpha**: Reconnaissance specialist using safe discovery tools
- **PlannerBeta**: Exploitation specialist using Burp Suite MCP tools  
- **WebPenTester**: Browser verification agent for visual confirmation

## Prerequisites

### System Requirements
- Python 3.11+ 
- Windows 10/11 (tested environment)
- Burp Suite Professional (for MCP integration)
- Chrome/Chromium browser (for WebPenTester)

### Required API Keys
- **OpenAI API Key**: For GPT models (o3-mini, gpt-4.1-mini, etc.)
- **Google Custom Search API**: For OSINT capabilities (optional)
- **Gemini API Key**: If using Gemini models (optional)

## Installation Steps

### 1. Environment Setup

```bash
# Clone or download the project
cd autogen-test

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. API Key Configuration

Create a `.env` file in the project root:

```env
# Required - OpenAI API Key
OPENAI_API_KEY=your_openai_api_key_here

# Optional - Google Search Integration
GOOGLE_API_KEY=your_google_api_key_here
GOOGLE_SEARCH_ENGINE_ID=your_custom_search_engine_id

# Optional - Gemini Integration
GOOGLE_API_KEY=your_gemini_api_key_here
```

### 3. Burp Suite MCP Setup

#### Install Burp MCP Server
1. Download the Burp MCP extension from PortSwigger's BApp Store
2. Load the extension in Burp Suite Professional
3. Configure MCP server to run on `http://127.0.0.1:9876/sse`
4. Ensure Burp proxy is running and configured

#### Test Burp Integration
```python
# Run the test script
python burptest.py
```

### 4. Tool Dependencies (Optional)

Some advanced tools require additional setup:

#### Aquatone (Visual Reconnaissance)
- Download from: https://github.com/michenriksen/aquatone
- Place executable in project directory
- Update Chrome path in `tools.py` if needed

#### FFUF (Directory Fuzzing)
```bash
# Download from: https://github.com/ffuf/ffuf
# Add to system PATH or place in project directory
```

#### Arjun (Parameter Discovery)
```bash
pip install arjun
```

## Configuration

### Model Selection
Edit `config.txt` to customize:

```txt
# Available models
DEFAULT_PLANNER_MODEL = "o3-mini"
DEFAULT_WEB_MODEL = "o3-mini"
AVAILABLE_PLANNER_MODELS = ["o3-mini", "o4-mini", "gpt-4.1-mini", "gpt-4o-mini", "gpt-4.1-nano", "gemini-2.0-flash"]
```

### Tool Categories
Customize which tools are enabled by default in `config.txt`:

```txt
TOOL_CATEGORIES = {
    "Reconnaissance": ["curl_headers_tool", "get_subdomains_tool", "arjun_tool"],
    "Security Analysis": ["pysslscan_tool", "google_search_tool"],
    "Utilities": ["bypasspayloads_tool", "writereport_tool"]
}
```

## Usage

### Standard Automated Mode

```bash
python main.py
```

**Interactive Prompts:**
1. Select AI model (o3-mini recommended)
2. Enter target URLs (comma-separated)
3. Choose advanced tools (y/n)
4. Set context window size
5. Define objective (default: admin login bypass)

### Human-in-the-Loop Mode

```bash
python main_humanloop.py
```

This mode emphasizes manual Burp Suite operations:
- Agents create Repeater tabs and Intruder attacks
- Human operator executes manual button presses
- Provides ready-to-paste HTTP requests and payload lists

## Project Structure

```
autogen-test/
├── main.py                 # Primary automated entry point
├── main_humanloop.py       # Human-in-the-loop variant
├── tools.py               # Core tool implementations
├── config.txt             # Agent prompts and configuration
├── requirements.txt       # Python dependencies
├── burptest.py           # Burp MCP integration test
├── src/                  # Supporting modules
│   ├── utils/
│   └── contextplus_memory.py
├── rag_app/              # RAG knowledge base
├── rag_data/             # Vector store data
├── sql_injection_docs/   # SQLi documentation
├── recon_agent/          # Subdomain enumeration
└── web_interface/        # Web UI (optional)
```



## Troubleshooting

### Common Issues

#### 1. Burp MCP Connection Failed
```
Error: Connection refused to 127.0.0.1:9876
```
**Solution:**
- Ensure Burp Suite is running
- Verify MCP extension is loaded and active
- Check firewall settings

#### 2. Tool Import Errors
```
ImportError: No module named 'beautifulsoup4'
```
**Solution:**
```bash
pip install beautifulsoup4 requests pillow
```

#### 3. API Rate Limiting
```
Error: Rate limit exceeded
```
**Solution:**
- Check API key quotas
- Reduce context window size
- Use cheaper models (gpt-4o-mini vs o3-mini)

#### 4. Browser Agent Fails
```
Error: Chrome not found
```
**Solution:**
- Install Chrome/Chromium
- Update browser path in `tools.py`
- Use headless=True for server environments

### Performance Optimization

#### Token Usage Reduction
- Use `context_window_size=8` (default)
- Enable response compression in config
- Disable advanced tools if not needed

#### Speed Improvements
- Use faster models (gpt-4.1-mini)
- Reduce tool selection
- Enable result caching


### Custom Prompts
Edit `config.txt` sections:
- `PLANNER_SYSTEM_MESSAGE`: Core agent behavior
- `SELECTOR_SYSTEM_MESSAGE`: Agent coordination
- `TOOL_USAGE_GUIDELINES`: Tool-specific instructions

### Adding New Tools
1. Implement function in `tools.py`
2. Create `FunctionTool` wrapper
3. Add to `TOOL_NAME_MAP`
4. Update `config.txt` categories

### Custom Payloads
Edit `tools.py`:
```python
ADMIN_BYPASS_PAYLOADS = [
    "' OR '1'='1' -- ",
    "your_custom_payload_here",
    # Add more payloads
]
```

## Support and Documentation

### Additional Resources
- `AGENT_WORKFLOW.md`: Detailed agent behavior documentation
- `GOOGLE_SEARCH_SETUP.md`: OSINT integration guide
- `sql_injection_docs/`: SQLi technique references
- Generated reports in project root

## Example Usage Session

```bash
# Start framework
python main.py

# Select model: 1 (o3-mini)
# Enter target: https://example.com/login
# Advanced tools: n
# Context size: 1 (Summary - 8 messages)
# Objective: [Enter] (use default)

# Framework will:
# 1. Discover forms and parameters
# 2. Test SQL injection payloads systematically  
# 3. Generate comprehensive report
# 4. Save findings to report.txt
