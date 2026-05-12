package models

// MCPOAuthAuthorizationCode represents a one-time OAuth authorization code for MCP.
type MCPOAuthAuthorizationCode struct {
	CodeHash        string `xorm:"PK VARCHAR(64)"`
	Uid             int64  `xorm:"INDEX(IDX_mcp_oauth_authorization_code_uid) NOT NULL"`
	ClientId        string `xorm:"TEXT NOT NULL"`
	RedirectUri     string `xorm:"TEXT NOT NULL"`
	Resource        string `xorm:"TEXT NOT NULL"`
	Scope           string `xorm:"VARCHAR(255) NOT NULL"`
	CodeChallenge   string `xorm:"VARCHAR(128) NOT NULL"`
	CreatedUnixTime int64  `xorm:"NOT NULL"`
	ExpiredUnixTime int64  `xorm:"INDEX(IDX_mcp_oauth_authorization_code_expired_time) NOT NULL"`
	UsedUnixTime    int64
}

// MCPOAuthRefreshToken represents an opaque refresh token for MCP OAuth.
type MCPOAuthRefreshToken struct {
	RefreshTokenHash string `xorm:"PK VARCHAR(64)"`
	Uid              int64  `xorm:"INDEX(IDX_mcp_oauth_refresh_token_uid) NOT NULL"`
	ClientId         string `xorm:"TEXT NOT NULL"`
	Resource         string `xorm:"TEXT NOT NULL"`
	Scope            string `xorm:"VARCHAR(255) NOT NULL"`
	CreatedUnixTime  int64  `xorm:"NOT NULL"`
	ExpiredUnixTime  int64  `xorm:"INDEX(IDX_mcp_oauth_refresh_token_expired_time) NOT NULL"`
	RevokedUnixTime  int64
}
