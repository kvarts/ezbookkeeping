package middlewares

import (
	"strings"

	"github.com/mayswind/ezbookkeeping/pkg/core"
	"github.com/mayswind/ezbookkeeping/pkg/errs"
	"github.com/mayswind/ezbookkeeping/pkg/mcp"
	"github.com/mayswind/ezbookkeeping/pkg/settings"
	"github.com/mayswind/ezbookkeeping/pkg/utils"
)

// MCPHTTPHeaders validates Streamable HTTP headers for MCP.
func MCPHTTPHeaders(config *settings.Config) core.MiddlewareHandlerFunc {
	return func(c *core.WebContext) {
		if c.Request == nil || c.Request.Method != "POST" {
			c.Next()
			return
		}

		accept := c.GetHeader("Accept")

		if !acceptsMCPResponse(accept) {
			utils.PrintJsonErrorResult(c, errs.ErrMCPAcceptHeaderInvalid)
			return
		}

		c.Next()
	}
}

// MCPOrigin validates browser Origin headers for MCP.
func MCPOrigin(config *settings.Config) core.MiddlewareHandlerFunc {
	return func(c *core.WebContext) {
		origin := c.GetHeader("Origin")

		if origin == "" {
			c.Next()
			return
		}

		for i := 0; i < len(config.MCPOAuthAllowedOrigins); i++ {
			if origin == config.MCPOAuthAllowedOrigins[i] {
				c.Next()
				return
			}
		}

		utils.PrintJsonErrorResult(c, errs.ErrMCPOriginForbidden)
	}
}

func acceptsMCPResponse(accept string) bool {
	if accept == "" {
		return false
	}

	parts := strings.Split(accept, ",")

	for i := 0; i < len(parts); i++ {
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(parts[i], ";")[0]))

		if mediaType == "*/*" || mediaType == "application/*" || mediaType == "application/json" || mediaType == "text/event-stream" {
			return true
		}
	}

	return false
}

func setMCPBearerChallenge(c *core.WebContext, config *settings.Config) {
	if config == nil || !config.MCPOAuthEnable {
		return
	}

	c.Header("WWW-Authenticate", `Bearer resource_metadata="`+mcp.ProtectedResourceMetadataURL(config)+`", scope="`+mcp.MCPReadScope+` `+mcp.MCPWriteScope+`"`)
}
