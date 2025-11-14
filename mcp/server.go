/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

// MCP protocol message structures
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP-specific structures
type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type CallToolResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server implements the MCP server
type Server struct {
	reader *bufio.Reader
	writer io.Writer
	ctx    context.Context
}

// NewServer creates a new MCP server
func NewServer(ctx context.Context, reader io.Reader, writer io.Writer) *Server {
	return &Server{
		reader: bufio.NewReader(reader),
		writer: writer,
		ctx:    ctx,
	}
}

// Run starts the MCP server and handles requests
func (s *Server) Run() error {
	// Initialize the Pelican client
	if err := config.InitClient(); err != nil {
		return fmt.Errorf("failed to initialize Pelican client: %w", err)
	}

	log.Info("Pelican MCP server started")

	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Info("Client disconnected")
				return nil
			}
			return fmt.Errorf("error reading request: %w", err)
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Errorf("Error parsing JSON-RPC request: %v", err)
			s.sendError(nil, -32700, "Parse error", nil)
			continue
		}

		log.Debugf("Received request: %s (ID: %v)", req.Method, req.ID)

		if err := s.handleRequest(&req); err != nil {
			log.Errorf("Error handling request: %v", err)
		}
	}
}

// handleRequest processes a JSON-RPC request
func (s *Server) handleRequest(req *JSONRPCRequest) error {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleListTools(req)
	case "tools/call":
		return s.handleCallTool(req)
	case "ping":
		return s.sendResponse(req.ID, map[string]interface{}{})
	default:
		return s.sendError(req.ID, -32601, "Method not found", nil)
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(req *JSONRPCRequest) error {
	var params InitializeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.sendError(req.ID, -32602, "Invalid params", err.Error())
	}

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		ServerInfo: ServerInfo{
			Name:    "pelican-mcp-server",
			Version: "1.0.0",
		},
	}

	return s.sendResponse(req.ID, result)
}

// handleListTools handles the tools/list request
func (s *Server) handleListTools(req *JSONRPCRequest) error {
	tools := []Tool{
		{
			Name:        "pelican_download",
			Description: "Download an object from a Pelican URL to a local destination. Supports both single files and recursive directory downloads.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL to download from (e.g., pelican://osg-htc.org/ospool/uc-shared/public/OSG-Staff/validation/test.txt)",
					},
					"destination": map[string]interface{}{
						"type":        "string",
						"description": "The local file path where the object should be saved",
					},
					"recursive": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, recursively download directories",
						"default":     false,
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"source", "destination"},
			},
		},
		{
			Name:        "pelican_stat",
			Description: "Get metadata information about a Pelican object, including size, modification time, and checksums.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL to get information about",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "pelican_list",
			Description: "List the contents of a directory in Pelican.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The Pelican URL of the directory to list",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Optional authentication token for accessing protected resources",
					},
				},
				"required": []string{"url"},
			},
		},
	}

	result := ListToolsResult{Tools: tools}
	return s.sendResponse(req.ID, result)
}

// handleCallTool handles the tools/call request
func (s *Server) handleCallTool(req *JSONRPCRequest) error {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.sendError(req.ID, -32602, "Invalid params", err.Error())
	}

	log.Infof("Calling tool: %s with arguments: %v", params.Name, params.Arguments)

	var result CallToolResult

	switch params.Name {
	case "pelican_download":
		result = s.handleDownload(params.Arguments)
	case "pelican_stat":
		result = s.handleStat(params.Arguments)
	case "pelican_list":
		result = s.handleList(params.Arguments)
	default:
		return s.sendError(req.ID, -32602, "Unknown tool", params.Name)
	}

	return s.sendResponse(req.ID, result)
}

// handleDownload implements the pelican_download tool
func (s *Server) handleDownload(args map[string]interface{}) CallToolResult {
	source, ok := args["source"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'source' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	destination, ok := args["destination"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'destination' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	recursive := false
	if r, ok := args["recursive"].(bool); ok {
		recursive = r
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(destination)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Error creating destination directory: %v", err)}},
			IsError: true,
		}
	}

	// Perform the download
	transferResults, err := client.DoGet(s.ctx, source, destination, recursive, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Download failed: %v", err)}},
			IsError: true,
		}
	}

	// Build success message
	var totalBytes int64
	for _, result := range transferResults {
		totalBytes += result.TransferredBytes
	}

	message := fmt.Sprintf("Successfully downloaded from %s to %s\n", source, destination)
	message += fmt.Sprintf("Files transferred: %d\n", len(transferResults))
	message += fmt.Sprintf("Total bytes: %d (%.2f MB)\n", totalBytes, float64(totalBytes)/(1024*1024))

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// handleStat implements the pelican_stat tool
func (s *Server) handleStat(args map[string]interface{}) CallToolResult {
	url, ok := args["url"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'url' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// Get file info
	fileInfo, err := client.DoStat(s.ctx, url, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("Stat failed: %v", err)}},
			IsError: true,
		}
	}

	// Build response message
	message := fmt.Sprintf("Object information for %s:\n", url)
	message += fmt.Sprintf("Name: %s\n", fileInfo.Name)
	message += fmt.Sprintf("Size: %d bytes (%.2f MB)\n", fileInfo.Size, float64(fileInfo.Size)/(1024*1024))
	message += fmt.Sprintf("Modified: %s\n", fileInfo.ModTime.Format("2006-01-02 15:04:05 MST"))
	message += fmt.Sprintf("Is Collection: %v\n", fileInfo.IsCollection)

	if len(fileInfo.Checksums) > 0 {
		message += "Checksums:\n"
		for algo, checksum := range fileInfo.Checksums {
			message += fmt.Sprintf("  %s: %s\n", algo, checksum)
		}
	}

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// handleList implements the pelican_list tool
func (s *Server) handleList(args map[string]interface{}) CallToolResult {
	url, ok := args["url"].(string)
	if !ok {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "Error: 'url' parameter is required and must be a string"}},
			IsError: true,
		}
	}

	// Build transfer options
	var options []client.TransferOption
	if token, ok := args["token"].(string); ok && token != "" {
		options = append(options, client.WithToken(token))
	}

	// List directory contents
	fileInfos, err := client.DoList(s.ctx, url, options...)
	if err != nil {
		return CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("List failed: %v", err)}},
			IsError: true,
		}
	}

	// Build response message
	message := fmt.Sprintf("Contents of %s:\n\n", url)
	for _, info := range fileInfos {
		typeStr := "file"
		if info.IsCollection {
			typeStr = "dir"
		}
		message += fmt.Sprintf("[%s] %s (%d bytes, modified: %s)\n",
			typeStr, info.Name, info.Size, info.ModTime.Format("2006-01-02 15:04:05"))
	}

	if len(fileInfos) == 0 {
		message += "(empty directory)\n"
	}

	return CallToolResult{
		Content: []ContentItem{{Type: "text", Text: message}},
		IsError: false,
	}
}

// sendResponse sends a JSON-RPC response
func (s *Server) sendResponse(id interface{}, result interface{}) error {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("error marshaling response: %w", err)
	}

	data = append(data, '\n')
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("error writing response: %w", err)
	}

	log.Debugf("Sent response for ID: %v", id)
	return nil
}

// sendError sends a JSON-RPC error response
func (s *Server) sendError(id interface{}, code int, message string, data interface{}) error {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("error marshaling error response: %w", err)
	}

	respData = append(respData, '\n')
	if _, err := s.writer.Write(respData); err != nil {
		return fmt.Errorf("error writing error response: %w", err)
	}

	log.Debugf("Sent error response for ID: %v", id)
	return nil
}
