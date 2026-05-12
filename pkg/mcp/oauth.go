package mcp

import (
	"strings"

	"github.com/mayswind/ezbookkeeping/pkg/settings"
)

// CanonicalMCPResource returns the canonical MCP resource URL.
func CanonicalMCPResource(config *settings.Config) string {
	return strings.TrimRight(config.RootUrl, "/") + "/mcp"
}

// ProtectedResourceMetadataURL returns the OAuth protected resource metadata URL for MCP.
func ProtectedResourceMetadataURL(config *settings.Config) string {
	return strings.TrimRight(config.RootUrl, "/") + "/.well-known/oauth-protected-resource/mcp"
}
