package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/mayswind/ezbookkeeping/pkg/core"
	"github.com/mayswind/ezbookkeeping/pkg/errs"
	"github.com/mayswind/ezbookkeeping/pkg/log"
	"github.com/mayswind/ezbookkeeping/pkg/mcp"
	"github.com/mayswind/ezbookkeeping/pkg/models"
	"github.com/mayswind/ezbookkeeping/pkg/services"
	"github.com/mayswind/ezbookkeeping/pkg/settings"
)

// MCPOAuthAPI represents MCP OAuth endpoints.
type MCPOAuthAPI struct {
	ApiUsingConfig
	users                   *services.UserService
	tokens                  *services.TokenService
	twoFactorAuthorizations *services.TwoFactorAuthorizationService
}

var MCPOAuth = &MCPOAuthAPI{
	ApiUsingConfig: ApiUsingConfig{
		container: settings.Container,
	},
	users:                   services.Users,
	tokens:                  services.Tokens,
	twoFactorAuthorizations: services.TwoFactorAuthorizations,
}

type mcpOAuthAuthorizeRequest struct {
	ResponseType        string
	ClientId            string
	RedirectUri         string
	State               string
	Resource            string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type mcpOAuthClientMetadata struct {
	ClientId                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectUris            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type mcpOAuthAuthorizePageData struct {
	Title        string
	Error        string
	AppName      string
	Resource     string
	Scope        string
	Params       map[string]string
	ShowLogin    bool
	LoginName    string
	ShowPasscode bool
}

var mcpOAuthAuthorizeTemplate = template.Must(template.New("mcp-oauth-authorize").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f7f7f5;color:#202124;margin:0;padding:32px}
main{max-width:520px;margin:0 auto;background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px}
h1{font-size:22px;margin:0 0 16px}
p{line-height:1.45}
label{display:block;font-weight:600;margin:14px 0 6px}
input{width:100%;box-sizing:border-box;border:1px solid #c8c8c8;border-radius:6px;padding:10px;font-size:15px}
button{margin-top:18px;background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:10px 14px;font-size:15px;cursor:pointer}
.secondary{background:#666}
.error{background:#fff1f0;border:1px solid #ffccc7;color:#a8071a;border-radius:6px;padding:10px;margin-bottom:14px}
.scope{font-family:ui-monospace,Menlo,monospace;background:#f1f3f4;border-radius:6px;padding:8px}
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="/oauth2/mcp/authorize">
{{range $key, $value := .Params}}<input type="hidden" name="{{$key}}" value="{{$value}}">
{{end}}
{{if .ShowLogin}}
<p>Sign in to ezBookkeeping to authorize this MCP client.</p>
<label for="login_name">Username or email</label>
<input id="login_name" name="login_name" value="{{.LoginName}}" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
{{if .ShowPasscode}}<label for="passcode">Two-factor passcode</label>
<input id="passcode" name="passcode" inputmode="numeric" autocomplete="one-time-code" required>{{end}}
<button type="submit">Continue</button>
{{else}}
<p><strong>{{.AppName}}</strong> is requesting access to ezBookkeeping.</p>
<p>Resource:</p>
<p class="scope">{{.Resource}}</p>
<p>Scopes:</p>
<p class="scope">{{.Scope}}</p>
<input type="hidden" name="approve" value="1">
<button type="submit">Authorize</button>
{{end}}
</form>
</main>
</body>
</html>`))

// ProtectedResourceMetadataHandler returns OAuth protected resource metadata.
func (a *MCPOAuthAPI) ProtectedResourceMetadataHandler(c *core.WebContext) {
	config := a.CurrentConfig()

	c.JSON(http.StatusOK, core.O{
		"resource":                 mcp.CanonicalMCPResource(config),
		"authorization_servers":    []string{config.MCPOAuthIssuer},
		"scopes_supported":         []string{mcp.MCPReadScope, mcp.MCPWriteScope},
		"bearer_methods_supported": []string{"header"},
	})
}

// AuthorizationServerMetadataHandler returns OAuth authorization server metadata.
func (a *MCPOAuthAPI) AuthorizationServerMetadataHandler(c *core.WebContext) {
	config := a.CurrentConfig()
	issuer := strings.TrimRight(config.MCPOAuthIssuer, "/")

	c.JSON(http.StatusOK, core.O{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/mcp/authorize",
		"token_endpoint":                        issuer + "/oauth2/mcp/token",
		"scopes_supported":                      []string{mcp.MCPReadScope, mcp.MCPWriteScope},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"client_id_metadata_document_supported": true,
	})
}

// AuthorizeHandler handles OAuth authorization requests.
func (a *MCPOAuthAPI) AuthorizeHandler(c *core.WebContext) {
	req, clientMetadata, err := a.validateAuthorizeRequest(c)

	if err != nil {
		a.renderAuthorizeError(c, "Invalid authorization request", err.Error())
		return
	}

	user, _ := a.currentUserFromCookie(c)
	showPasscode := false

	if user == nil && c.Request.Method == http.MethodPost && c.PostForm("login_name") != "" {
		user, showPasscode, err = a.loginFromAuthorizeForm(c)

		if err != nil {
			a.renderAuthorizePage(c, req, clientMetadata, true, showPasscode, c.PostForm("login_name"), err.Error())
			return
		}
	}

	if user == nil {
		a.renderAuthorizePage(c, req, clientMetadata, true, showPasscode, "", "")
		return
	}

	if user.FeatureRestriction.Contains(core.USER_FEATURE_RESTRICTION_TYPE_MCP_ACCESS) {
		a.renderAuthorizeError(c, "Access denied", "This user is not permitted to use MCP.")
		return
	}

	if c.Request.Method != http.MethodPost || c.PostForm("approve") != "1" {
		a.renderAuthorizePage(c, req, clientMetadata, false, false, "", "")
		return
	}

	code, createErr := a.tokens.CreateMCPOAuthAuthorizationCode(c, user.Uid, req.ClientId, req.RedirectUri, req.Resource, req.Scope, req.CodeChallenge)

	if createErr != nil {
		log.Errorf(c, "[mcp_oauth.AuthorizeHandler] failed to create authorization code for user \"uid:%d\", because %s", user.Uid, createErr.Error())
		a.renderAuthorizeError(c, "Authorization failed", errs.ErrOperationFailed.Error())
		return
	}

	redirectUri, parseErr := url.Parse(req.RedirectUri)

	if parseErr != nil {
		a.renderAuthorizeError(c, "Invalid redirect URI", parseErr.Error())
		return
	}

	values := redirectUri.Query()
	values.Set("code", code)

	if req.State != "" {
		values.Set("state", req.State)
	}

	redirectUri.RawQuery = values.Encode()
	c.Redirect(http.StatusFound, redirectUri.String())
}

// TokenHandler handles OAuth token requests.
func (a *MCPOAuthAPI) TokenHandler(c *core.WebContext) {
	if !a.CurrentConfig().MCPOAuthEnable {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_request", errs.ErrMCPOAuthNotEnabled.Error())
		return
	}

	if err := c.Request.ParseForm(); err != nil {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	grantType := c.PostForm("grant_type")

	if grantType == "authorization_code" {
		a.exchangeAuthorizationCode(c)
		return
	}

	if grantType == "refresh_token" {
		a.exchangeRefreshToken(c)
		return
	}

	a.writeOAuthError(c, http.StatusBadRequest, "unsupported_grant_type", errs.ErrMCPOAuthUnsupportedGrantType.Error())
}

func (a *MCPOAuthAPI) exchangeAuthorizationCode(c *core.WebContext) {
	clientId := c.PostForm("client_id")
	code := c.PostForm("code")
	redirectUri := c.PostForm("redirect_uri")
	resource := c.PostForm("resource")
	codeVerifier := c.PostForm("code_verifier")

	record, err := a.tokens.GetMCPOAuthAuthorizationCode(c, code)

	if err != nil || record.UsedUnixTime > 0 || record.ExpiredUnixTime <= time.Now().Unix() {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	if record.ClientId != clientId || record.RedirectUri != redirectUri || record.Resource != resource || !validPKCEVerifier(codeVerifier, record.CodeChallenge) {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	user, err := a.users.GetUserById(c, record.Uid)

	if err != nil || user.Disabled || user.FeatureRestriction.Contains(core.USER_FEATURE_RESTRICTION_TYPE_MCP_ACCESS) {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	if err = a.tokens.MarkMCPOAuthAuthorizationCodeUsed(c, record); err != nil {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	a.issueTokenPair(c, user, record.ClientId, record.Resource, record.Scope)
}

func (a *MCPOAuthAPI) exchangeRefreshToken(c *core.WebContext) {
	clientId := c.PostForm("client_id")
	resource := c.PostForm("resource")
	refreshToken := c.PostForm("refresh_token")

	record, err := a.tokens.GetMCPOAuthRefreshToken(c, refreshToken)

	if err != nil || record.RevokedUnixTime > 0 || record.ExpiredUnixTime <= time.Now().Unix() {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	if record.ClientId != clientId || (resource != "" && record.Resource != resource) {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	user, err := a.users.GetUserById(c, record.Uid)

	if err != nil || user.Disabled || user.FeatureRestriction.Contains(core.USER_FEATURE_RESTRICTION_TYPE_MCP_ACCESS) {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	if err = a.tokens.RevokeMCPOAuthRefreshToken(c, record); err != nil {
		a.writeOAuthError(c, http.StatusBadRequest, "invalid_grant", errs.ErrMCPOAuthInvalidGrant.Error())
		return
	}

	a.issueTokenPair(c, user, record.ClientId, record.Resource, record.Scope)
}

func (a *MCPOAuthAPI) issueTokenPair(c *core.WebContext, user *models.User, clientId string, resource string, scope string) {
	accessToken, _, err := a.tokens.CreateMCPOAuthAccessToken(c, user, clientId, resource, scope)

	if err != nil {
		a.writeOAuthError(c, http.StatusInternalServerError, "server_error", errs.ErrTokenGenerating.Error())
		return
	}

	refreshToken, err := a.tokens.CreateMCPOAuthRefreshToken(c, user.Uid, clientId, resource, scope)

	if err != nil {
		a.writeOAuthError(c, http.StatusInternalServerError, "server_error", errs.ErrTokenGenerating.Error())
		return
	}

	c.JSON(http.StatusOK, core.O{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    a.CurrentConfig().MCPOAuthAccessTokenExpiredTime,
		"refresh_token": refreshToken,
		"scope":         scope,
	})
}

func (a *MCPOAuthAPI) validateAuthorizeRequest(c *core.WebContext) (*mcpOAuthAuthorizeRequest, *mcpOAuthClientMetadata, error) {
	if !a.CurrentConfig().MCPOAuthEnable {
		return nil, nil, errs.ErrMCPOAuthNotEnabled
	}

	if err := c.Request.ParseForm(); err != nil {
		return nil, nil, err
	}

	req := &mcpOAuthAuthorizeRequest{
		ResponseType:        c.Request.Form.Get("response_type"),
		ClientId:            c.Request.Form.Get("client_id"),
		RedirectUri:         c.Request.Form.Get("redirect_uri"),
		State:               c.Request.Form.Get("state"),
		Resource:            c.Request.Form.Get("resource"),
		Scope:               normalizeMCPScope(c.Request.Form.Get("scope")),
		CodeChallenge:       c.Request.Form.Get("code_challenge"),
		CodeChallengeMethod: c.Request.Form.Get("code_challenge_method"),
	}

	if req.ResponseType != "code" || req.ClientId == "" || req.RedirectUri == "" || req.Resource == "" || req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return nil, nil, errs.ErrMCPOAuthInvalidRequest
	}

	if req.Resource != mcp.CanonicalMCPResource(a.CurrentConfig()) || !validRequestedMCPScope(req.Scope) {
		return nil, nil, errs.ErrMCPOAuthInvalidRequest
	}

	clientMetadata, err := a.fetchClientMetadata(req.ClientId)

	if err != nil {
		return nil, nil, err
	}

	if !stringSliceContains(clientMetadata.RedirectUris, req.RedirectUri) {
		return nil, nil, errs.ErrMCPOAuthInvalidClient
	}

	return req, clientMetadata, nil
}

func (a *MCPOAuthAPI) fetchClientMetadata(clientId string) (*mcpOAuthClientMetadata, error) {
	clientURL, err := url.Parse(clientId)

	if err != nil || clientURL.Scheme != "https" || clientURL.Host == "" {
		return nil, errs.ErrMCPOAuthInvalidClient
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(clientId)

	if err != nil {
		return nil, errs.ErrMCPOAuthInvalidClient
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.ErrMCPOAuthInvalidClient
	}

	var metadata mcpOAuthClientMetadata

	if err = json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, errs.ErrMCPOAuthInvalidClient
	}

	if metadata.ClientId != clientId ||
		metadata.TokenEndpointAuthMethod != "none" ||
		!stringSliceContains(metadata.ResponseTypes, "code") ||
		!stringSliceContains(metadata.GrantTypes, "authorization_code") ||
		!stringSliceContains(metadata.GrantTypes, "refresh_token") {
		return nil, errs.ErrMCPOAuthInvalidClient
	}

	return &metadata, nil
}

func (a *MCPOAuthAPI) currentUserFromCookie(c *core.WebContext) (*models.User, error) {
	tokenString := c.GetTokenStringFromCookie()

	if tokenString == "" {
		return nil, errs.ErrUnauthorizedAccess
	}

	token, claims, _, err := a.tokens.ParseToken(c, tokenString)

	if err != nil || token == nil || !token.Valid || claims == nil {
		return nil, errs.ErrUnauthorizedAccess
	}

	if claims.Type != core.USER_TOKEN_TYPE_NORMAL && claims.Type != core.USER_TOKEN_TYPE_API {
		return nil, errs.ErrUnauthorizedAccess
	}

	return a.users.GetUserById(c, claims.Uid)
}

func (a *MCPOAuthAPI) loginFromAuthorizeForm(c *core.WebContext) (*models.User, bool, error) {
	if !a.CurrentConfig().EnableInternalAuth {
		return nil, false, errs.ErrCannotLoginByPassword
	}

	loginName := c.PostForm("login_name")
	password := c.PostForm("password")
	passcode := c.PostForm("passcode")
	user, _, err := a.users.GetUserByUsernameOrEmailAndPassword(c, loginName, password)

	if err != nil {
		return nil, false, errs.ErrLoginNameOrPasswordWrong
	}

	if user.Disabled {
		return nil, false, errs.ErrUserIsDisabled
	}

	if a.CurrentConfig().EnableUserForceVerifyEmail && !user.EmailVerified {
		return nil, false, errs.ErrEmailIsNotVerified
	}

	twoFactorEnable := a.CurrentConfig().EnableTwoFactor

	if twoFactorEnable {
		twoFactorEnable, err = a.twoFactorAuthorizations.ExistsTwoFactorSetting(c, user.Uid)

		if err != nil {
			return nil, false, errs.ErrOperationFailed
		}
	}

	if twoFactorEnable {
		twoFactorSetting, err := a.twoFactorAuthorizations.GetUserTwoFactorSettingByUid(c, user.Uid)

		if err != nil {
			return nil, true, errs.ErrOperationFailed
		}

		if passcode == "" || !totp.Validate(passcode, twoFactorSetting.Secret) {
			return nil, true, errs.ErrPasscodeInvalid
		}
	}

	if err = a.users.UpdateUserLastLoginTime(c, user.Uid); err != nil {
		log.Warnf(c, "[mcp_oauth.loginFromAuthorizeForm] failed to update last login time for user \"uid:%d\", because %s", user.Uid, err.Error())
	}

	token, _, err := a.tokens.CreateToken(c, user)

	if err != nil {
		return nil, false, errs.ErrTokenGenerating
	}

	c.SetTokenStringToCookie(token, int(a.CurrentConfig().TokenExpiredTime), "/")
	return user, false, nil
}

func (a *MCPOAuthAPI) renderAuthorizePage(c *core.WebContext, req *mcpOAuthAuthorizeRequest, clientMetadata *mcpOAuthClientMetadata, showLogin bool, showPasscode bool, loginName string, errorText string) {
	appName := clientMetadata.ClientName

	if appName == "" {
		appName = req.ClientId
	}

	params := map[string]string{
		"response_type":         req.ResponseType,
		"client_id":             req.ClientId,
		"redirect_uri":          req.RedirectUri,
		"resource":              req.Resource,
		"scope":                 req.Scope,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
	}

	if req.State != "" {
		params["state"] = req.State
	}

	data := &mcpOAuthAuthorizePageData{
		Title:        "Authorize MCP Access",
		Error:        errorText,
		AppName:      appName,
		Resource:     req.Resource,
		Scope:        req.Scope,
		Params:       params,
		ShowLogin:    showLogin,
		LoginName:    loginName,
		ShowPasscode: showPasscode,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = mcpOAuthAuthorizeTemplate.Execute(c.Writer, data)
}

func (a *MCPOAuthAPI) renderAuthorizeError(c *core.WebContext, title string, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusBadRequest)
	_ = mcpOAuthAuthorizeTemplate.Execute(c.Writer, &mcpOAuthAuthorizePageData{
		Title: title,
		Error: message,
	})
}

func (a *MCPOAuthAPI) writeOAuthError(c *core.WebContext, statusCode int, code string, description string) {
	c.JSON(statusCode, core.O{
		"error":             code,
		"error_description": description,
	})
}

func normalizeMCPScope(scope string) string {
	scope = strings.TrimSpace(scope)

	if scope == "" {
		return mcp.MCPReadScope + " " + mcp.MCPWriteScope
	}

	return strings.Join(strings.Fields(scope), " ")
}

func validRequestedMCPScope(scope string) bool {
	scopes := strings.Fields(scope)

	if len(scopes) < 1 {
		return false
	}

	for i := 0; i < len(scopes); i++ {
		if scopes[i] != mcp.MCPReadScope && scopes[i] != mcp.MCPWriteScope {
			return false
		}
	}

	return true
}

func validPKCEVerifier(verifier string, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func stringSliceContains(items []string, value string) bool {
	for i := 0; i < len(items); i++ {
		if items[i] == value {
			return true
		}
	}

	return false
}
