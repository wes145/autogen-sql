# server.py
from mcp.server.fastmcp import FastMCP
import subprocess

# Create an MCP server
mcp = FastMCP("SecurityTools")


# Add an addition tool
@mcp.tool()
def arjun(
    url: str = None,
    textFile: str = None,
    wordlist: str = None,
    method: str = None,
    rateLimit: int = 9999,
    chunkSize: int = None
) -> str:
    """Discover hidden HTTP parameters using Arjun. At least one of url or textFile is required."""
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

@mcp.tool()
def do_sslscan(target: str, sslscan_args: list = None) -> str:
    """Run SSLScan on a target. sslscan_args is a list of extra arguments."""
    cmd = ["pysslscan", target]
    if sslscan_args:
        cmd += sslscan_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"[sslscan error] {e}"

if __name__ == "__main__":
    mcp.run()

"