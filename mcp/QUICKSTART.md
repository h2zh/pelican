# Quick Setup Guide for Claude Desktop on macOS

## Current Status
✅ All MCP server code is implemented and pushed to your branch
✅ Latest fix (e8df70f) addresses the initialization error you saw

## Steps to Build and Test on Your Mac

### 1. Pull the Latest Code on Your Mac

```bash
cd /Users/hzhong/Documents/dev/pelican-0821/pelican
git fetch origin
git checkout claude/pelican-client-mcp-support-01U8iKkCZme9tbToj9FojN3Y
git pull origin claude/pelican-client-mcp-support-01U8iKkCZme9tbToj9FojN3Y
```

### 2. Build for macOS

```bash
cd /Users/hzhong/Documents/dev/pelican-0821/pelican/cmd
go build -o pelican .
```

This creates: `/Users/hzhong/Documents/dev/pelican-0821/pelican/cmd/pelican`

### 3. Verify the Build

```bash
./pelican --version
./pelican mcp --help
```

You should see the `mcp serve` command listed.

### 4. Configure Claude Desktop

Edit: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "pelican": {
      "command": "/Users/hzhong/Documents/dev/pelican-0821/pelican/cmd/pelican",
      "args": ["mcp", "serve"]
    }
  }
}
```

**Important:** Use the full absolute path to the binary you just built.

### 5. Restart Claude Desktop

Press `Cmd+Q` to fully quit Claude Desktop, then reopen it.

### 6. Test the MCP Connection

In Claude Desktop, you should see an MCP indicator. Look for "pelican" in the list of connected servers.

### 7. Test with a Download

In the chat, type:

```
Download pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt to /tmp/test.txt
```

### 8. Verify Success

```bash
cat /tmp/test.txt
```

You should see: `If you are seeing this message, getting an object from OSDF was successful.`

## What Was Fixed

The error you saw (`Invalid input`, `id required`, `method required`) was caused by:
- The server tried to initialize the Pelican client at startup
- Any output (logs/errors) went to stdout and corrupted the JSON-RPC stream
- Claude Desktop couldn't parse the malformed JSON

**The fix:**
- Server now starts immediately without initialization
- Pelican client initializes lazily (only when first tool is called)
- All logs go to stderr, stdout is clean JSON-RPC only
- Proper error handling within the JSON-RPC protocol

## Troubleshooting

If you still see errors:

1. **Check logs**: `~/Library/Logs/Claude/mcp*.log`
2. **Test manually**:
   ```bash
   /Users/hzhong/Documents/dev/pelican-0821/pelican/cmd/pelican mcp serve
   ```
   Then type: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`

   You should get a JSON response (not an error)

3. **Check binary is executable**: `chmod +x /Users/hzhong/Documents/dev/pelican-0821/pelican/cmd/pelican`

## Available Tools

Once connected, Claude can use:

- **pelican_download** - Download files/directories from Pelican URLs
- **pelican_stat** - Get metadata about objects (size, time, checksums)
- **pelican_list** - List directory contents

## Example Prompts

```
Download pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt to ~/Downloads/test.txt

Get information about pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt

List the contents of pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/
```

Good luck! 🚀
