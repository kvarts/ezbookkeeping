package errs

import "net/http"

// Error codes related to model context protocol server
var (
	ErrMCPServerNotEnabled          = NewNormalError(NormalSubcategoryModelContextProtocol, 0, http.StatusBadRequest, "mcp server is not enabled")
	ErrMCPProtocolVersionInvalid    = NewNormalError(NormalSubcategoryModelContextProtocol, 1, http.StatusBadRequest, "mcp protocol version is invalid")
	ErrMCPAcceptHeaderInvalid       = NewNormalError(NormalSubcategoryModelContextProtocol, 2, http.StatusNotAcceptable, "mcp accept header is invalid")
	ErrMCPOriginForbidden           = NewNormalError(NormalSubcategoryModelContextProtocol, 3, http.StatusForbidden, "mcp origin is forbidden")
	ErrMCPInsufficientScope         = NewNormalError(NormalSubcategoryModelContextProtocol, 4, http.StatusForbidden, "mcp token has insufficient scope")
	ErrMCPOAuthNotEnabled           = NewNormalError(NormalSubcategoryModelContextProtocol, 5, http.StatusBadRequest, "mcp oauth is not enabled")
	ErrMCPOAuthInvalidRequest       = NewNormalError(NormalSubcategoryModelContextProtocol, 6, http.StatusBadRequest, "invalid mcp oauth request")
	ErrMCPOAuthInvalidClient        = NewNormalError(NormalSubcategoryModelContextProtocol, 7, http.StatusBadRequest, "invalid mcp oauth client")
	ErrMCPOAuthInvalidGrant         = NewNormalError(NormalSubcategoryModelContextProtocol, 8, http.StatusBadRequest, "invalid mcp oauth grant")
	ErrMCPOAuthUnsupportedGrantType = NewNormalError(NormalSubcategoryModelContextProtocol, 9, http.StatusBadRequest, "unsupported mcp oauth grant type")
)
