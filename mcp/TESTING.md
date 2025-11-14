# Testing Pelican MCP Server with Cline

This guide walks you through testing the Pelican MCP server with Cline in Cursor.

## Prerequisites

1. **Build Pelican with MCP support**

   From the pelican repository root, build the binary:
   ```bash
   # Option 1: Using goreleaser (recommended)
   make pelican-build
   # The binary will be in: dist/pelican_linux_amd64/pelican

   # Option 2: Simple Go build (for testing)
   cd cmd && go build -o pelican .
   ```

2. **Install the pelican binary**

   Make sure `pelican` is accessible in your PATH:
   ```bash
   # Option 1: Copy to a directory in PATH
   sudo cp dist/pelican_linux_amd64/pelican /usr/local/bin/

   # Option 2: Add to PATH temporarily
   export PATH=$PATH:/path/to/pelican/dist/pelican_linux_amd64

   # Verify installation
   which pelican
   pelican --version
   ```

3. **Verify MCP command exists**
   ```bash
   pelican mcp --help
   ```

   You should see:
   ```
   Start a Model Context Protocol (MCP) server that exposes Pelican client
   functionality to AI assistants and other MCP clients.

   Usage:
     pelican mcp [command]

   Available Commands:
     serve       Start the MCP server
   ```

## Configuration

You've already configured Cline correctly! Your settings at:
`/root/.cursor-server/data/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "pelican": {
      "command": "pelican",
      "args": ["mcp", "serve"]
    }
  }
}
```

## Testing Steps

### 1. Restart Cursor/Cline

After modifying the MCP settings, you **must restart Cursor** for the changes to take effect.

### 2. Open Cline

In Cursor, open the Cline extension (usually a chat icon in the sidebar).

### 3. Check MCP Server Status

Look for an indicator showing that the Pelican MCP server is connected. Cline typically shows:
- A list of available MCP servers
- Their connection status (green = connected, red = error)

If there's an error, check the Cline logs for details.

### 4. Test with Your Prompt

In the Cline chat, enter your prompt:

```
Download pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt to /tmp/test.txt
```

**What should happen:**
1. Cline recognizes this is a download request
2. Cline calls the `pelican_download` tool via MCP
3. The MCP server executes the download using Pelican client
4. Cline reports the results back to you

Expected output:
```
Successfully downloaded from pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt to /tmp/test.txt
Files transferred: 1
Total bytes: 27 (0.00 MB)
```

### 5. Verify the Download

Check that the file was actually downloaded:
```bash
ls -lh /tmp/test.txt
cat /tmp/test.txt
```

You should see:
```
If you are seeing this message, getting an object from OSDF was successful.
```

## Additional Test Cases

### Test 2: Get File Metadata

```
Get information about the file at pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt
```

Expected: Cline uses `pelican_stat` tool and shows file size, modification time, etc.

### Test 3: List Directory

```
List the contents of pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/
```

Expected: Cline uses `pelican_list` tool and shows directory contents.

### Test 4: Recursive Download

```
Download the entire validation directory from pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/ to /tmp/validation/ recursively
```

Expected: Cline uses `pelican_download` with `recursive: true`.

## Troubleshooting

### MCP Server Won't Start

**Check logs:**
Look at Cline's output panel for MCP server logs. Errors will be shown there.

**Common issues:**
- `pelican` not in PATH → Solution: Verify `which pelican` returns a path
- Permission denied → Solution: Ensure pelican binary is executable (`chmod +x pelican`)
- Wrong config path → Solution: Double-check the JSON file location

**Test manually:**
```bash
# Test the MCP server directly
pelican mcp serve
```

Then type (as one line of JSON):
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
```

Press Enter. You should see a JSON response. Press Ctrl+D to exit.

### Cline Doesn't Use the Tool

If Cline responds but doesn't call the Pelican tools:

1. **Check tool visibility**: Ask Cline: "What tools do you have access to?"
2. **Be explicit**: Say "Use the pelican_download tool to download..."
3. **Check MCP connection**: Look for the Pelican MCP server in Cline's MCP status

### Download Fails

If the tool is called but download fails:

1. **Check network**: Ensure you can reach the Pelican federation
2. **Test manually**: Try `pelican object get pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt /tmp/manual-test.txt`
3. **Check logs**: The MCP server logs to stderr, visible in Cline's output panel

### Can't Find MCP Settings File

Cline MCP settings location varies by platform:
- **Linux**: `~/.cursor-server/data/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **macOS**: `~/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- **Windows**: `%APPDATA%\Cursor\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

You can also configure it through Cline's UI: Open Cline → Settings → MCP Servers

## Debug Mode

Enable debug logging to see more details:

```json
{
  "mcpServers": {
    "pelican": {
      "command": "pelican",
      "args": ["mcp", "serve", "--debug"]
    }
  }
}
```

Restart Cursor after making this change.

## Success Indicators

You'll know it's working when:
1. ✅ Cline shows "Pelican MCP server: Connected" (or similar)
2. ✅ When you ask to download, you see Cline calling the tool
3. ✅ The file appears at `/tmp/test.txt`
4. ✅ You can cat the file and see the expected content

## Next Steps

Once basic download works, try:
- Downloading from different namespaces
- Using authentication tokens for protected resources
- Recursive directory downloads
- Getting metadata and listing directories

Good luck! 🚀
