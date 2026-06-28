package buildkite

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func newOAuthServiceForTest(t *testing.T, client *Client) *OAuthService {
	oauth := &OAuthService{client: client, tokenEndpoint: OAuthTokenEndpoint}
	return oauth
}

// customJTIGenerator is a test generator that returns predictable JTIs.
func customJTIGenerator() string {
	return "custom-jti-" + uuid.NewString()
}

// fakeClientAssertion is a placeholder JWT string used only in tests.
const fakeClientAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

func TestOAuthService_Exchange(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %v, want application/x-www-form-urlencoded", got)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}

		// Verify auto-set fields
		if got := r.Form.Get("grant_type"); got != GrantTypeTokenExchange {
			t.Errorf("grant_type = %v, want %v", got, GrantTypeTokenExchange)
		}
		if got := r.Form.Get("client_assertion_type"); got != ClientAssertionTypeJWTBearer {
			t.Errorf("client_assertion_type = %v, want %v", got, ClientAssertionTypeJWTBearer)
		}
		if got := r.Form.Get("subject_token_type"); got != SubjectTokenTypeUserEmail {
			t.Errorf("subject_token_type = %v, want %v", got, SubjectTokenTypeUserEmail)
		}
		if got := r.Form.Get("client_assertion"); got != fakeClientAssertion {
			t.Errorf("client_assertion = %v, want %v", got, fakeClientAssertion)
		}
		if got := r.Form.Get("subject_token"); got != "user@example.com" {
			t.Errorf("subject_token = %v, want user@example.com", got)
		}
		if got := r.Form.Get("audience"); got != "my-org" {
			t.Errorf("audience = %v, want my-org", got)
		}

		_, _ = fmt.Fprint(w, `{
			"access_token": "bktx_abc123",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer",
			"expires_in": 3600,
			"scope": "read_pipelines read_builds"
		}`)
	})

	resp, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})
	if err != nil {
		t.Fatalf("OAuth.Exchange returned error: %v", err)
	}

	want := &TokenExchangeResponse{
		AccessToken:     "bktx_abc123",
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		Scope:           "read_pipelines read_builds",
	}
	if diff := cmp.Diff(resp, want); diff != "" {
		t.Errorf("OAuth.Exchange diff: (-got +want)\n%s", diff)
	}
}

func TestOAuthService_Exchange_WithScopes(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}

		// Scopes should be sorted and joined with spaces
		if got := r.Form.Get("scope"); got != "read_pipelines write_builds" {
			t.Errorf("scope = %v, want 'read_pipelines write_builds'", got)
		}
		if got := r.Form.Get("expires_in"); got != "7200" {
			t.Errorf("expires_in = %v, want 7200", got)
		}
		if got := r.Form.Get("jti"); got != "test-jti-123" {
			t.Errorf("jti = %v, want test-jti-123", got)
		}

		_, _ = fmt.Fprint(w, `{
			"access_token": "bktx_xyz789",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer",
			"expires_in": 7200,
			"scope": "read_pipelines write_builds"
		}`)
	})

	resp, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		SubjectToken:    "admin@example.com",
		Audience:        "acme-corp",
		Scopes:          []string{"write_builds", "read_pipelines"}, // unsorted input
		ExpiresIn:       7200,
		JTI:             "test-jti-123",
	})
	if err != nil {
		t.Fatalf("OAuth.Exchange returned error: %v", err)
	}

	if resp.Scope != "read_pipelines write_builds" {
		t.Errorf("Scope = %v, want 'read_pipelines write_builds'", resp.Scope)
	}
	if resp.ExpiresIn != 7200 {
		t.Errorf("ExpiresIn = %v, want 7200", resp.ExpiresIn)
	}
}

func TestOAuthService_Exchange_ScopesSorting(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	var capturedScope string
	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		capturedScope = r.Form.Get("scope")
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	// Pass scopes in different orders - should produce same serialized scope
	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "test",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
		Scopes:          []string{"z", "a", "m"},
	})
	if err != nil {
		t.Fatalf("Exchange() returned error: %v", err)
	}

	if capturedScope != "a m z" {
		t.Errorf("scope = %v, want 'a m z' (sorted)", capturedScope)
	}
}

func TestOAuthService_Exchange_AutoJTI(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	var capturedJTI string
	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		capturedJTI = r.Form.Get("jti")
		if capturedJTI == "" {
			t.Error("jti was not set")
		}
		// Verify JTI looks like a UUID (36 chars with hyphens)
		if len(capturedJTI) != 36 {
			t.Errorf("jti doesn't look like a UUID: %v", capturedJTI)
		}
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})
	if err != nil {
		t.Fatalf("OAuth.Exchange returned error: %v", err)
	}

	t.Logf("Captured JTI: %s", capturedJTI)
}

func TestOAuthService_Exchange_CustomJTI(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	var capturedJTI string
	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		capturedJTI = r.Form.Get("jti")
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	te, err := oauth.NewTokenExchanger(TokenExchangerConfig{
		ClientID:            "client123",
		ClientAssertionFunc: func(jti string) (string, error) { return "signed-" + jti, nil },
		Audience:            "my-org",
		SubjectToken:        "user@example.com",
		JTIGenerator:        customJTIGenerator,
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger() error = %v", err)
	}

	_, _, err = te.Exchange(context.Background())
	if err != nil {
		t.Fatalf("Exchange() returned error: %v", err)
	}

	// Verify custom JTI was used
	if !strings.HasPrefix(capturedJTI, "custom-jti-") {
		t.Errorf("expected custom JTI prefix, got: %v", capturedJTI)
	}
}

func TestOAuthService_Exchange_MissingClientAssertion(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		SubjectToken: "user@example.com",
		Audience:     "my-org",
	})
	if err == nil {
		t.Error("expected error for missing client_assertion")
	}
}

func TestOAuthService_Exchange_MissingSubjectToken(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		Audience:        "my-org",
	})
	if err == nil {
		t.Error("expected error for missing subject_token")
	}
}

func TestOAuthService_Exchange_MissingAudience(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		SubjectToken:    "user@example.com",
	})
	if err == nil {
		t.Error("expected error for missing audience")
	}
}

func TestOAuthService_Exchange_OAuthError(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error": "invalid_client", "error_description": "JWT has already been used (jti)"}`)
	})

	_, resp, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: fakeClientAssertion,
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})

	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected *OAuthError, got %T", err)
	}
	if oauthErr.Error() != "invalid_client: JWT has already been used (jti)" {
		t.Errorf("OAuthError.Error() = %v, want 'invalid_client: JWT has already been used (jti)'", oauthErr.Error())
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestOAuthService_Exchange_ErrorResponse(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error": "invalid_client", "error_description": "Invalid client assertion signature"}`)
	})

	_, resp, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "invalid-assertion",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})

	if err == nil {
		t.Fatal("expected error for invalid client assertion")
	}
	oauthErr, ok := err.(*OAuthError)
	if !ok {
		t.Fatalf("expected *OAuthError, got %T", err)
	}
	if oauthErr.Code != "invalid_client" {
		t.Errorf("OAuthError.Code = %v, want 'invalid_client'", oauthErr.Code)
	}
	if oauthErr.Description != "Invalid client assertion signature" {
		t.Errorf("OAuthError.Description = %v, want 'Invalid client assertion signature'", oauthErr.Description)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %v, want %v", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestOAuthService_Exchange_NonOAuthError(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"message":"Internal server error"}`)
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "test-assertion",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})

	if err == nil {
		t.Fatal("expected error for server error response")
	}
	// Non-OAuth errors should NOT be parsed as *OAuthError since they lack the "error" field
	if _, ok := err.(*OAuthError); ok {
		t.Errorf("expected non-OAuth error, got *OAuthError: %v", err)
	}
	// The error should contain the message text
	errResp, ok := err.(*ErrorResponse)
	if !ok {
		t.Fatalf("expected *ErrorResponse, got %T", err)
	}
	if errResp.Message != "Internal server error" {
		t.Errorf("ErrorResponse.Message = %v, want 'Internal server error'", errResp.Message)
	}
}

func TestTokenExchanger_NewTokenExchanger(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	defer func() { _ = server }()

	oauth := newOAuthServiceForTest(t, client)

	tests := []struct {
		name    string
		cfg     TokenExchangerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: TokenExchangerConfig{
				ClientID:            "client123",
				ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
				Audience:            "my-org",
				SubjectToken:        "user@example.com",
			},
			wantErr: false,
		},
		{
			name: "valid config with custom JTI generator",
			cfg: TokenExchangerConfig{
				ClientID:            "client123",
				ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
				Audience:            "my-org",
				SubjectToken:        "user@example.com",
				JTIGenerator:        customJTIGenerator,
			},
			wantErr: false,
		},
		{
			name: "missing client ID",
			cfg: TokenExchangerConfig{
				ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
				Audience:            "my-org",
				SubjectToken:        "user@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing client assertion func",
			cfg: TokenExchangerConfig{
				ClientID:     "client123",
				Audience:     "my-org",
				SubjectToken: "user@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			cfg: TokenExchangerConfig{
				ClientID:            "client123",
				ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
				SubjectToken:        "user@example.com",
			},
			wantErr: true,
		},
		{
			name: "missing subject token",
			cfg: TokenExchangerConfig{
				ClientID:            "client123",
				ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
				Audience:            "my-org",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oauth.NewTokenExchanger(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenExchanger() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenExchanger_Exchange(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	te, err := oauth.NewTokenExchanger(TokenExchangerConfig{
		ClientID:            "client123",
		ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt-" + jti, nil },
		Audience:            "my-org",
		SubjectToken:        "user@example.com",
		Scopes:              []string{"read_pipelines"},
		ExpiresIn:           3600,
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger() error = %v", err)
	}

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}

		if got := r.Form.Get("scope"); got != "read_pipelines" {
			t.Errorf("scope = %v, want read_pipelines", got)
		}
		if got := r.Form.Get("expires_in"); got != "3600" {
			t.Errorf("expires_in = %v, want 3600", got)
		}

		_, _ = fmt.Fprint(w, `{
			"access_token": "bktx_token123",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer",
			"expires_in": 3600,
			"scope": "read_pipelines"
		}`)
	})

	resp, _, err := te.Exchange(context.Background())
	if err != nil {
		t.Fatalf("TokenExchanger.Exchange() returned error: %v", err)
	}

	if resp.AccessToken != "bktx_token123" {
		t.Errorf("AccessToken = %v, want bktx_token123", resp.AccessToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %v, want 3600", resp.ExpiresIn)
	}
}

func TestTokenExchanger_Exchange_ScopesSorted(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	var capturedScope string
	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		capturedScope = r.Form.Get("scope")
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	te, err := oauth.NewTokenExchanger(TokenExchangerConfig{
		ClientID:            "client123",
		ClientAssertionFunc: func(jti string) (string, error) { return "signed-jwt", nil },
		Audience:            "my-org",
		SubjectToken:        "user@example.com",
		Scopes:              []string{"z", "a", "m"}, // unsorted
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger() error = %v", err)
	}

	_, _, err = te.Exchange(context.Background())
	if err != nil {
		t.Fatalf("Exchange() returned error: %v", err)
	}

	if capturedScope != "a m z" {
		t.Errorf("scope = %v, want 'a m z' (sorted)", capturedScope)
	}
}

func TestTokenExchanger_Exchange_ClientAssertionFuncError(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	te, err := oauth.NewTokenExchanger(TokenExchangerConfig{
		ClientID:            "client123",
		ClientAssertionFunc: func(jti string) (string, error) { return "", fmt.Errorf("signing failed") },
		Audience:            "my-org",
		SubjectToken:        "user@example.com",
	})
	if err != nil {
		t.Fatalf("NewTokenExchanger() error = %v", err)
	}

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called when client assertion func fails")
	})

	_, _, err = te.Exchange(context.Background())
	if err == nil {
		t.Error("expected error when ClientAssertionFunc fails")
	}
}

func TestOAuthError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      OAuthError
		expected string
	}{
		{
			name:     "with description",
			err:      OAuthError{Code: "invalid_client", Description: "JWT has already been used"},
			expected: "invalid_client: JWT has already been used",
		},
		{
			name:     "without description",
			err:      OAuthError{Code: "invalid_request"},
			expected: "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("OAuthError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestOAuthConstants(t *testing.T) {
	t.Parallel()

	if GrantTypeTokenExchange != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("GrantTypeTokenExchange = %v, want urn:ietf:params:oauth:grant-type:token-exchange", GrantTypeTokenExchange)
	}
	if ClientAssertionTypeJWTBearer != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("ClientAssertionTypeJWTBearer = %v, want urn:ietf:params:oauth:client-assertion-type:jwt-bearer", ClientAssertionTypeJWTBearer)
	}
	if SubjectTokenTypeUserEmail != "urn:buildkite:params:oauth:token-type:user-email" {
		t.Errorf("SubjectTokenTypeUserEmail = %v, want urn:buildkite:params:oauth:token-type:user-email", SubjectTokenTypeUserEmail)
	}
	if IssuedTokenTypeAccessToken != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("IssuedTokenTypeAccessToken = %v, want urn:ietf:params:oauth:token-type:access_token", IssuedTokenTypeAccessToken)
	}
	if OAuthTokenEndpoint != "/oauth/token" {
		t.Errorf("OAuthTokenEndpoint = %v, want /oauth/token", OAuthTokenEndpoint)
	}
	if DefaultOAuthTokenEndpoint != "https://buildkite.com/oauth/token" {
		t.Errorf("DefaultOAuthTokenEndpoint = %v, want https://buildkite.com/oauth/token", DefaultOAuthTokenEndpoint)
	}
}

func TestOAuthService_Exchange_FormEncoding(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		if ctype := r.Header.Get("Content-Type"); !strings.Contains(ctype, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %v, want application/x-www-form-urlencoded", ctype)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if !strings.Contains(string(body), "grant_type=") {
			t.Error("body should contain grant_type")
		}
		if !strings.Contains(string(body), "client_assertion=") {
			t.Error("body should contain client_assertion")
		}
		if !strings.Contains(string(body), "subject_token=") {
			t.Error("body should contain subject_token")
		}

		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "test-assertion",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})
	if err != nil {
		t.Fatalf("OAuth.Exchange returned error: %v", err)
	}
}

func TestDefaultJTIGenerator(t *testing.T) {
	t.Parallel()

	jti1 := DefaultJTIGenerator()
	jti2 := DefaultJTIGenerator()

	// Should be valid UUID format (36 chars with hyphens)
	if len(jti1) != 36 {
		t.Errorf("jti1 length = %v, want 36 (UUID format)", len(jti1))
	}

	// Should be unique
	if jti1 == jti2 {
		t.Error("consecutive calls to DefaultJTIGenerator should produce unique JTIs")
	}
}

func TestSortScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    []string
		expected []string
	}{
		{[]string{"z", "a", "m"}, []string{"a", "m", "z"}},
		{[]string{"read", "write"}, []string{"read", "write"}},
		{[]string{"write", "read"}, []string{"read", "write"}},
		{[]string{}, nil},
		{nil, nil},
	}

	for _, tt := range tests {
		result := sortScopes(tt.input)
		if !cmp.Equal(result, tt.expected) {
			t.Errorf("sortScopes(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestOAuthService_Exchange_AbsoluteTokenEndpoint(t *testing.T) {
	t.Parallel()

	server, client, teardown := newMockServerAndClient(t)
	t.Cleanup(teardown)

	oauth := NewOAuthService(client, client.BaseURL.String()+"/oauth/token")

	server.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "test-assertion",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})
	if err != nil {
		t.Fatalf("OAuth.Exchange returned error: %v", err)
	}
}

func TestOAuthService_Exchange_RetryOn429(t *testing.T) {
	t.Parallel()

	callCount := 0
	var receivedBodies []string

	ms, client, teardown := newRetryTestClient(t)
	t.Cleanup(teardown)
	oauth := newOAuthServiceForTest(t, client)

	ms.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		if callCount == 1 {
			w.Header().Set("RateLimit-Reset", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token": "bktx_test", "token_type": "Bearer", "expires_in": 3600}`)
	})

	_, _, err := oauth.Exchange(context.Background(), TokenExchangeRequest{
		ClientAssertion: "test-assertion",
		SubjectToken:    "user@example.com",
		Audience:        "my-org",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 server calls, got %d", callCount)
	}
	for i, body := range receivedBodies {
		if body == "" {
			t.Errorf("call %d received empty body — request body was not replayed on retry", i+1)
		}
		if receivedBodies[0] != body {
			t.Errorf("call %d body %q differs from call 1 body %q", i+1, body, receivedBodies[0])
		}
	}
}

func TestRedactAssertion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "redacts client_assertion in form body",
			input:    "grant_type=exchange&client_assertion=FAKE_JWT_VALUE&subject_token=user@example.com",
			expected: "grant_type=exchange&client_assertion=REDACTED&subject_token=user@example.com",
		},
		{
			name:     "redacts client_assertion at end of string",
			input:    "client_assertion=secret",
			expected: "client_assertion=REDACTED",
		},
		{
			name:     "no client_assertion",
			input:    "grant_type=exchange&subject_token=user@example.com",
			expected: "grant_type=exchange&subject_token=user@example.com",
		},
		{
			name:     "multiple client_assertions",
			input:    "client_assertion=secret1&client_assertion=secret2",
			expected: "client_assertion=REDACTED&client_assertion=REDACTED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(redactAssertion([]byte(tt.input)))
			if got != tt.expected {
				t.Errorf("redactAssertion() = %v, want %v", got, tt.expected)
			}
		})
	}
}