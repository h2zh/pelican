# Pelican MCP Server

The Pelican Model Context Protocol (MCP) server allows AI assistants and other MCP clients to interact with Pelican federations for downloading files, getting file metadata, and listing directories.

## Overview

The MCP server exposes Pelican client functionality as tools that can be called by AI assistants. It uses JSON-RPC 2.0 over stdin/stdout for communication, following the [Model Context Protocol specification](https://spec.modelcontextprotocol.io/).

## Features

The Pelican MCP server provides three main tools:

1. **pelican_download** - Download objects from Pelican URLs
2. **pelican_stat** - Get metadata about Pelican objects
3. **pelican_list** - List contents of Pelican directories

## Usage

### Starting the MCP Server

```bash
pelican mcp serve
```

The server will read JSON-RPC requests from stdin and write responses to stdout. It's designed to be launched by an MCP client (such as Claude Desktop, Cline, or other AI assistants with MCP support).

### Configuring with Claude Desktop

To use the Pelican MCP server with Claude Desktop, add it to your MCP configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

After adding the configuration, restart Claude Desktop. The Pelican tools will be available in your conversations.

### Configuring with Cline (VS Code Extension)

In VS Code, open the Cline MCP settings and add:

```json
{
  "pelican": {
    "command": "pelican",
    "args": ["mcp", "serve"]
  }
}
```

## Tools Documentation

### pelican_download

Downloads an object from a Pelican URL to a local destination.

**Parameters:**
- `source` (string, required): The Pelican URL to download from
  - Example: `pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt`
- `destination` (string, required): The local file path where the object should be saved
  - Example: `/tmp/test.txt`
- `recursive` (boolean, optional): If true, recursively download directories (default: false)
- `token` (string, optional): Authentication token for accessing protected resources

**Example:**
```
User: Download pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt to /tmp/test.txt