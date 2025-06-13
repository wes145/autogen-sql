# Google Custom Search API Setup Guide

This guide explains how to set up Google Custom Search API for the penetration testing tools.

## Required Environment Variables

Add these to your `.env` file:

```bash
# Google Custom Search API Configuration
GOOGLE_API_KEY=your_google_api_key_here
GOOGLE_SEARCH_ENGINE_ID=your_custom_search_engine_id_here
```

## Step-by-Step Setup

### 1. Get Google API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Custom Search API**:
   - Go to "APIs & Services" > "Library"
   - Search for "Custom Search API"
   - Click "Enable"
4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "API Key"
   - Copy the API key and add it to your `.env` file as `GOOGLE_API_KEY`

### 2. Create Custom Search Engine

1. Go to [Google Custom Search Engine](https://cse.google.com/)
2. Click "Add" to create a new search engine
3. Configure your search engine:
   - **Sites to search**: Add `*.*` to search the entire web, or add specific security sites:
     - `portswigger.net`
     - `owasp.org`
     - `cve.mitre.org`
     - `exploit-db.com`
     - `github.com`
   - **Language**: English
   - **Name**: "Pentesting Security Search" (or your preference)
4. Click "Create"
5. Copy the **Search Engine ID** and add it to your `.env` file as `GOOGLE_SEARCH_ENGINE_ID`

### 3. Configure Search Engine (Optional)

1. In your Custom Search Engine settings:
   - Turn on "Image search" if needed
   - Turn on "Safe Search" to OFF for security research
   - Add more sites as needed

## Available Search Tools

### `google_search_tool(query, num_results=5, site_filter=None)`

General Google search with security context enhancement.

**Examples:**
```python
google_search_tool("SQL injection bypass WAF")
google_search_tool("XSS payload 2024", num_results=10)
google_search_tool("authentication bypass", site_filter="portswigger.net")
```

### `security_sites_search_tool(query, num_results=3)`

Searches across multiple security-focused websites automatically.

**Examples:**
```python
security_sites_search_tool("SQL injection UNION attack")
security_sites_search_tool("privilege escalation techniques")
```

## Usage in Agents

The planner agents can now use these tools for real-time research:

1. **RAG first**: Use `query_rag_function_tool` for cached knowledge
2. **Google search**: Use `google_search_tool` for current techniques
3. **Security sites**: Use `security_sites_search_tool` for authoritative sources

## Cost Considerations

- Google Custom Search API provides 100 free searches per day
- Additional searches cost $5 per 1000 queries
- Monitor usage in Google Cloud Console

## Troubleshooting

### "API Key not found" error
- Check that `GOOGLE_API_KEY` is set in your `.env` file
- Ensure the Custom Search API is enabled in Google Cloud Console

### "Search Engine ID not found" error
- Check that `GOOGLE_SEARCH_ENGINE_ID` is set correctly
- Verify the Search Engine ID in Google Custom Search Console

### "Quota exceeded" error
- You've exceeded the free daily limit of 100 searches
- Either wait for quota reset or enable billing in Google Cloud Console

## Security Notes

- Keep your API key secure and don't commit it to version control
- Use environment variables or secure secret management
- Consider rotating API keys periodically
- Monitor API usage for unexpected activity 