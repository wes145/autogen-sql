# MCP for Security Tools

This repository contains Model Context Protocol (MCP) server implementations for various security testing tools, making them accessible through a standardized interface.

## Available Tools

| Tool | Description | Detailed Documentation |
|------|-------------|------------------------|
| Amass | Advanced subdomain enumeration and reconnaissance tool | [Amass MCP Documentation](./amass-mcp) |
| Alterx | Pattern-based wordlist generator for subdomain discovery | [Alterx MCP Documentation](./alterx-mcp/) |
| Arjun | Run Arjun to discover hidden HTTP parameters | [Arjun MCP Documentation](./arjun-mcp) |
| Assetfinder | Passive subdomain discovery tool based on Tomnomnom’s Assetfinder | [Assetfinder MCP Documentation](./assetfinder-mcp) |
| Certificate Search (crt.sh) | Subdomain discovery tool using SSL certificate logs | [Certificate Search MCP Documentation](./crtsh-mcp/) |
| FFUF | Web content fuzzing tool for discovering hidden files and directories | [FFUF MCP Documentation](./ffuf-mcp/) |
| HTTP Headers Security | Analyzer for HTTP security headers against OWASP standards | [HTTP Headers MCP Documentation](./http-headers-security-mcp/) |
| httpx | Fast and multi-purpose HTTP toolkit for port scanning. | [httpx MCP Documentation](./httpx-mcp) |
| Katana | Fast and flexible web crawler with JS parsing and hybrid crawling support | [Katana MCP Documentation](./katana-mcp/) |
| Masscan | Fast port scanner for large-scale network discovery | [Masscan MCP Documentation](./masscan-mcp/) |
| MobSF | Mobile security framework for analyzing mobile applications | [MobSF MCP Documentation](./mobsf-mcp/) |
| Nmap | Comprehensive network scanning tool for service and vulnerability discovery | [Nmap MCP Documentation](./nmap-mcp/) |
| Nuclei | Vulnerability scanner using custom templates | [Nuclei MCP Documentation](./nuclei-mcp/) |
| Scout Suite | Cloud security auditing tool for assessing configurations across multiple services | [Scout Suite MCP Documentation](./scoutsuite-mcp/) |
| SSLScan | SSL/TLS configuration analyzer for security assessment | [SSLScan MCP Documentation](./sslscan-mcp/) |
| shuffledns | High-speed and customizable DNS brute-forcing and resolution tool | [shuffledns MCP Documentation](./shuffledns-mcp) |
| SQLmap | Advanced SQL injection detection and exploitation tool | [SQLmap MCP Documentation](./sqlmap-mcp/) |
| Waybackurls | Tool for retrieving historical URLs from the Wayback Machine | [Waybackurls MCP Documentation](./waybackurls-mcp/) |

## Quick Reference

### Alterx MCP  
Generates custom wordlists for subdomain discovery using pattern-based permutations.

### Amass MCP  
Advanced reconnaissance tool for subdomain enumeration and intelligence gathering with both passive and active modes.

### arjun MCP  
Discovers hidden HTTP parameters on web applications by scanning URLs, supporting custom wordlists, multiple methods, and adjustable scanning speeds.

### Assetfinder MCP
Discovers subdomains related to a given domain using passive enumeration techniques. Integrates Tomnomnom’s Assetfinder into the MCP ecosystem for fast and reliable reconnaissance.

### Certificate Search (crt.sh) MCP  
Discovers subdomains by querying SSL certificate transparency logs without active scanning.

### FFUF MCP Server  
URL-based fuzzing tool with support for all FFUF command line arguments.

### HTTP Headers Security MCP  
Analyzes HTTP response headers against OWASP security standards with recommendations.

### httpx MCP  
Performs high-speed probing of discovered subdomains to validate alive hosts, fetch response details, and enrich reconnaissance data without heavy scanning.

### Katana MCP 
Performs fast and customizable web crawling to discover endpoints, scripts, and hidden paths. Supports JavaScript parsing, depth control, and hybrid crawling with headless browsers to enrich reconnaissance and automation workflows.

### Masscan MCP Server  
Fast port scanning tool for target-based port discovery across networks.

### MobSF MCP Server  
Mobile application security testing framework for Android, iOS, and Windows applications.

### Nmap MCP Server  
Full-featured network scanner with detailed service fingerprinting and vulnerability detection.

### Nuclei MCP Server  
Template-based vulnerability scanner with an extensive library of security checks.

### Scout Suite MCP Server 
Performs a multi-service cloud security audit by analyzing cloud configurations and highlighting potential misconfigurations and risks based on best practices.

### shuffledns MCP  
High-speed DNS brute-forcing and mass subdomain resolution tool to quickly discover valid subdomains using custom resolvers and wordlists.

### SQLmap MCP Server  
SQL injection testing tool with comprehensive capabilities for vulnerability discovery.

### SSLScan MCP Server  
SSL/TLS configuration analyzer for identifying weak ciphers and security misconfigurations.

### Waybackurls MCP  
Retrieves historical URLs from the Wayback Machine to discover forgotten endpoints.

## TO-DO Tools 
- cero
- commix
- Corsy
- CrackMapExec
- crlfuzz
- dalfox
- dnsrecon
- feroxbuster
- gau
- getJS
- github-endpoints
- github-subdomains
- gobuster
- gospider
- gowitness
- hakrawler
- kiterunner
- medusa
- naabu
- ParamSpider
- puredns
- s3scanner
- tlsx
- wafw00f
- webscreenshot
- wpscan
- ...

## Development

The project uses TypeScript and the Model Context Protocol SDK. To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Installation

For installation instructions for each tool, please refer to the individual documentation linked in the table above.

## Usage

Each tool has specific parameters and usage instructions. For detailed information, see the documentation for the specific tool you want to use.

## License
