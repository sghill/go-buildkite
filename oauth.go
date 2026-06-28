package buildkite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	GrantTypeTokenExchange       = "urn:ietf:params:oauth:grant-type:token-exchange"
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	SubjectTokenTypeUserEmail    = "urn:buildkite:params:oauth:token-type:user-email"
	IssuedTokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	// OAuthTokenEndpoint is the relative path for the OAuth token endpoint.
	OAuthTokenEndpoint = "/oauth/token"
	// DefaultOAuthTokenEndpoint is the production OAuth token endpoint URL.
	DefaultOAuthTokenEndpoint = "https://buildkite.com/oauth/token"
)

// OAuthService handles communication with the OAuth token exchange endpoint.
//
// buildkite API docs: https://buildkite.com/docs/apis/oauth-token-exchange
type OAuthService struct {
	client        *Client
	tokenEndpoint string // defaults to DefaultOAuthTokenEndpoint
}

// NewOAuthService creates an OAuthService with a custom token endpoint.
// This is useful for testing or alternative deployments.
func NewOAuthService(client *Client, tokenEndpoint string) *OAuthService {
	if tokenEndpoint == "" {
		tokenEndpoint = DefaultOAuthTokenEndpoint
	}
	return &OAuthService{client: client, tokenEndpoint: tokenEndpoint}
}

// TokenExchangeRequest contains the parameters for a token exchange request.
type TokenExchangeRequest struct {
	// ClientAssertion is a signed JWT assertion that authenticates the client.
	// The JWT must be signed with the client's private key and include claims:
	// - iss: client ID
	// - sub: client ID (must match iss)
	// - aud: https://buildkite.com/oauth/token
	// - iat: issued-at timestamp
	// - exp: expiration timestamp (within 5 minutes of iat)
	// - jti: unique identifier (optional, auto-generated if not provided)
	ClientAssertion string

	// SubjectToken is the email address of the Buildkite user to act as.
	// The user must be an active member of the target organization.
	SubjectToken string

	// Audience is the Buildkite organization slug (from the URL, not display name).
	Audience string

	// Scopes are the OAuth scopes to request.
	// Scopes are sorted internally for consistent serialization.
	// When serialized for the API, scopes are joined with spaces.
	Scopes []string

	// ExpiresIn requests a specific token TTL in seconds.
	// If omitted, the app's maximum TTL is used.
	// Capped by the app's configured maximum.
	ExpiresIn int

	// JTI overrides the auto-generated JTI. Typically not needed.
	JTI string
}

// TokenExchangeResponse represents the response from a token exchange request.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"` // API returns space-separated
}

// Scopes returns the scope string split into a slice of individual scopes.
// Returns nil if Scope is empty.
func (r TokenExchangeResponse) Scopes() []string {
	if r.Scope == "" {
		return nil
	}
	return strings.Split(r.Scope, " ")
}

// OAuthError represents an OAuth error response (RFC 6749 §5.2).
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// Error implements the error interface.
func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// JTIGenerator generates unique JWT IDs.
// The default implementation uses UUID.
type JTIGenerator func() string

// DefaultJTIGenerator generates unique JTIs using UUID.
func DefaultJTIGenerator() string {
	return uuid.NewString()
}

// TokenExchangerConfig contains configuration for creating a TokenExchanger.
type TokenExchangerConfig struct {
	// ClientID is the OAuth application's client ID.
	ClientID string

	// ClientAssertionFunc is called to build a signed JWT assertion.
	// The function receives the JTI and should return a signed JWT string.
	// Use a JWT library like github.com/golang-jwt/jwt/v5 to implement this.
	ClientAssertionFunc func(jti string) (string, error)

	// Audience is the Buildkite organization slug (from the URL).
	Audience string

	// SubjectToken is the email address of the Buildkite user to act as.
	SubjectToken string

	// Scopes are the OAuth scopes to request.
	// Scopes are sorted internally for consistent serialization.
	// When serialized for the API, scopes are joined with spaces.
	Scopes []string

	// ExpiresIn requests a specific token TTL in seconds.
	// If omitted, the app's maximum TTL is used.
	ExpiresIn int

	// JTIGenerator generates unique JTIs for each request.
	// Defaults to DefaultJTIGenerator (UUID-based).
	JTIGenerator JTIGenerator
}

// TokenExchanger provides a higher-level interface for OAuth token exchange
// with automatic JTI generation and client assertion building.
type TokenExchanger struct {
	oauth        *OAuthService
	config       TokenExchangerConfig
	jtiGenerator JTIGenerator
}

// NewTokenExchanger creates a new TokenExchanger with the specified configuration.
func (oas *OAuthService) NewTokenExchanger(cfg TokenExchangerConfig) (*TokenExchanger, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.ClientAssertionFunc == nil {
		return nil, fmt.Errorf("client assertion function is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}
	if cfg.SubjectToken == "" {
		return nil, fmt.Errorf("subject token is required")
	}

	te := &TokenExchanger{
		oauth:        oas,
		config:       cfg,
		jtiGenerator: cfg.JTIGenerator,
	}

	if te.jtiGenerator == nil {
		te.jtiGenerator = DefaultJTIGenerator
	}

	return te, nil
}

// Exchange performs an OAuth token exchange using the configured parameters.
// JTI is auto-generated for each request, and client assertion is built using
// the provided ClientAssertionFunc.
func (te *TokenExchanger) Exchange(ctx context.Context) (*TokenExchangeResponse, *Response, error) {
	// Generate JTI using the configured generator
	jti := te.jtiGenerator()

	// Build client assertion using the provided function
	clientAssertion, err := te.config.ClientAssertionFunc(jti)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build client assertion: %w", err)
	}

	req := TokenExchangeRequest{
		ClientAssertion: clientAssertion,
		SubjectToken:    te.config.SubjectToken,
		Audience:        te.config.Audience,
		Scopes:          te.config.Scopes,
		ExpiresIn:       te.config.ExpiresIn,
		JTI:             jti,
	}

	return te.oauth.Exchange(ctx, req)
}

// Exchange performs an OAuth token exchange request.
//
// The following fields are automatically set if not provided:
//   - grant_type: urn:ietf:params:oauth:grant-type:token-exchange
//   - client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//   - subject_token_type: urn:buildkite:params:oauth:token-type:user-email
//
// If JTI is not provided, a new unique ID is generated using the default UUID generator.
func (oas *OAuthService) Exchange(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, *Response, error) {
	if req.ClientAssertion == "" {
		return nil, nil, fmt.Errorf("client_assertion is required")
	}
	if req.SubjectToken == "" {
		return nil, nil, fmt.Errorf("subject_token is required")
	}
	if req.Audience == "" {
		return nil, nil, fmt.Errorf("audience is required")
	}

	// Auto-generate JTI if not provided
	if req.JTI == "" {
		req.JTI = DefaultJTIGenerator()
	}

	// Sort scopes for consistent serialization
	scopes := sortScopes(req.Scopes)

	// Build form data with auto-set fields
	formData := url.Values{
		"grant_type":            []string{GrantTypeTokenExchange},
		"client_assertion_type": []string{ClientAssertionTypeJWTBearer},
		"client_assertion":      []string{req.ClientAssertion},
		"subject_token":         []string{req.SubjectToken},
		"subject_token_type":    []string{SubjectTokenTypeUserEmail},
		"audience":              []string{req.Audience},
	}

	if len(scopes) > 0 {
		formData.Set("scope", strings.Join(scopes, " "))
	}

	if req.ExpiresIn > 0 {
		formData.Set("expires_in", fmt.Sprintf("%d", req.ExpiresIn))
	}

	if req.JTI != "" {
		formData.Set("jti", req.JTI)
	}

	// Use the service's token endpoint (can be absolute or relative)
	tokenEndpoint := oas.tokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = DefaultOAuthTokenEndpoint
	}

	httpReq, err := oas.client.NewRequest(ctx, "POST", tokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var tokenResp TokenExchangeResponse
	resp, err := oas.client.Do(httpReq, &tokenResp)
	if err != nil {
		// Check if it's an ErrorResponse with raw body we can parse as OAuthError
		if errResp, ok := err.(*ErrorResponse); ok && len(errResp.RawBody) > 0 {
			var oauthErr OAuthError
			if decodeErr := json.Unmarshal(errResp.RawBody, &oauthErr); decodeErr == nil && oauthErr.Code != "" {
				return nil, resp, &oauthErr
			}
		}
		return nil, resp, err
	}

	return &tokenResp, resp, nil
}

// sortScopes returns a sorted copy of the scopes slice for consistent serialization.
func sortScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return sorted
}
