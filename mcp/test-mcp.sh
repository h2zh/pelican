#!/bin/bash
# Test script for Pelican MCP server
# This simulates what Claude Desktop does when connecting

echo "Testing Pelican MCP server..."
echo ""

PELICAN_BIN="${1:-./cmd/pelican}"

if [ ! -f "$PELICAN_BIN" ]; then
    echo "Error: pelican binary not found at $PELICAN_BIN"
    echo "Usage: $0 [path-to-pelican-binary]"
    exit 1
fi

echo "Using pelican binary: $PELICAN_BIN"
echo ""

# Start the MCP server in the background
$PELICAN_BIN mcp serve 2>mcp-test.log &
MCP_PID=$!

# Give it a moment to start
sleep 1

# Check if it's still running
if ! kill -0 $MCP_PID 2>/dev/null; then
    echo "❌ MCP server failed to start"
    cat mcp-test.log
    exit 1
fi

echo "✓ MCP server started (PID: $MCP_PID)"
echo ""

# Function to send JSON-RPC request
send_request() {
    local request="$1"
    local description="$2"

    echo "Sending: $description"
    echo "$request" | nc localhost 9999 2>/dev/null || echo "$request" >&${MCP_PID}
}

# Test 1: Initialize
echo "Test 1: Initialize"
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | $PELICAN_BIN mcp serve 2>>mcp-test.log &
INIT_PID=$!
sleep 1
kill $INIT_PID 2>/dev/null
echo "✓ Initialize test completed"
echo ""

# Test 2: Check for "initialized" notification handling
echo "Test 2: Initialized notification"
echo '{"jsonrpc":"2.0","method":"initialized"}' | $PELICAN_BIN mcp serve 2>>mcp-test.log &
NOTIF_PID=$!
sleep 1
kill $NOTIF_PID 2>/dev/null
echo "✓ Initialized notification test completed"
echo ""

# Cleanup
kill $MCP_PID 2>/dev/null
wait $MCP_PID 2>/dev/null

echo ""
echo "Logs from MCP server:"
echo "===================="
cat mcp-test.log
echo "===================="
echo ""

if grep -qi "error\|panic\|fatal" mcp-test.log; then
    echo "❌ Errors found in log"
    exit 1
else
    echo "✅ All basic tests passed!"
    echo ""
    echo "To test with Claude Desktop:"
    echo "1. Update claude_desktop_config.json with path to pelican binary"
    echo "2. Restart Claude Desktop (Cmd+Q, then reopen)"
    echo "3. Check for 'pelican' in MCP servers list"
fi

rm -f mcp-test.log
