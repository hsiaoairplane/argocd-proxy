package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParsePolicyCSV(t *testing.T) {
	tests := []struct {
		name                                string
		policyCSV                           string
		expectedUserToObjectPatternMapping  map[string][]string
		expectedGroupToObjectPatternMapping map[string][]string
	}{
		{
			name: "Valid policy CSV with single team ALPHA READ ONLY",
			policyCSV: `
				g, admin@gmail.com, role:admin
				g, admin@hotmail.com, role:readonly
				p, team-alpha-readonly, applications, get, alpha1-*, allow
				p, team-alpha-readonly, applications, get, alpha2-*/*, allow
				p, team-alpha-readonly, applications, get, alpha3-*, allow
				p, team-alpha-readonly, applications, get, alpha4-*/*, allow
				g, ALPHA READ ONLY, team-alpha-readonly
				g, ALPHA READ ONLY_TW, team-alpha-readonly
				g, foobar@gmail.com, team-alpha-readonly
			`,
			expectedUserToObjectPatternMapping: map[string][]string{
				"admin@gmail.com": {
					"*",
				},
				"admin@hotmail.com": {
					"*",
				},
				"foobar@gmail.com": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
					"alpha4-*",
				},
			},
			expectedGroupToObjectPatternMapping: map[string][]string{
				"ALPHA READ ONLY": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
					"alpha4-*",
				},
				"ALPHA READ ONLY_TW": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
					"alpha4-*",
				},
			},
		},
		{
			name: "Valid policy CSV with multiple teams ALPHA READ ONLY and BETA READ ONLY",
			policyCSV: `
				g, admin@gmail.com, role:admin
				g, admin@hotmail.com, role:readonly
				p, team-alpha-readonly, applications, get, alpha1-*, allow
				p, team-alpha-readonly, applications, get, alpha2-*, allow
				p, team-alpha-readonly, applications, get, alpha3-*/*, allow
				g, ALPHA READ ONLY, team-alpha-readonly
				g, ALPHA READ ONLY_TW, team-alpha-readonly
				p, team-beta-readonly, applications, get, beta-*/*, allow
				g, BETA READ ONLY, team-beta-readonly
				g, BETA READ ONLY_TW, team-beta-readonly
				g, barfoo@gmail.com, team-beta-readonly
			`,
			expectedUserToObjectPatternMapping: map[string][]string{
				"admin@gmail.com": {
					"*",
				},
				"admin@hotmail.com": {
					"*",
				},
				"barfoo@gmail.com": {
					"beta-*",
				},
			},
			expectedGroupToObjectPatternMapping: map[string][]string{
				"ALPHA READ ONLY": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
				},
				"ALPHA READ ONLY_TW": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
				},
				"BETA READ ONLY": {
					"beta-*",
				},
				"BETA READ ONLY_TW": {
					"beta-*",
				},
			},
		},
		{
			name: "Valid policy CSV with single group but without role",
			policyCSV: `
				g, GAMMA READ ONLY, team-gamma-readonly
			`,
			expectedUserToObjectPatternMapping: map[string][]string{},
			expectedGroupToObjectPatternMapping: map[string][]string{
				"GAMMA READ ONLY": {},
			},
		},
		{
			name: "Valid policy CSV with single role but without group",
			policyCSV: `
				p, team-gamma-readonly, applications, get, gamma-*, allow
			`,
			expectedUserToObjectPatternMapping:  map[string][]string{},
			expectedGroupToObjectPatternMapping: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userToObjectPatternMapping, groupToObjectPatternMapping := parsePolicyCSV(tt.policyCSV)
			if !reflect.DeepEqual(userToObjectPatternMapping, tt.expectedUserToObjectPatternMapping) {
				t.Errorf("Expected user %v, but got user %v", tt.expectedUserToObjectPatternMapping, userToObjectPatternMapping)
			}
			if !reflect.DeepEqual(groupToObjectPatternMapping, tt.expectedGroupToObjectPatternMapping) {
				t.Errorf("Expected group %v, but got group %v", tt.expectedGroupToObjectPatternMapping, groupToObjectPatternMapping)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  func() *http.Request
		expectedToken string
	}{
		{
			name: "Valid Bearer Token in Authorization Header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer valid_token")
				return req
			},
			expectedToken: "valid_token",
		},
		{
			name: "Token in Cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "argocd.token", Value: "cookie_token"})
				return req
			},
			expectedToken: "cookie_token",
		},
		{
			name: "No Token in Header or Cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				return req
			},
			expectedToken: "",
		},
		{
			name: "Invalid Authorization Header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "InvalidAuth valid_token")
				return req
			},
			expectedToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			token := extractToken(req)

			if token != tt.expectedToken {
				t.Errorf("extractToken() = %q, want %q", token, tt.expectedToken)
			}
		})
	}
}

func TestDecodeJWTPayload(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		expected       map[string]interface{}
		expectingError bool
	}{
		{
			name:           "Valid JWT Token",
			token:          createTestJWT(map[string]interface{}{"email": "test@example.com", "role": "admin"}),
			expected:       map[string]interface{}{"email": "test@example.com", "role": "admin"},
			expectingError: false,
		},
		{
			name:           "Invalid JWT Token Format",
			token:          "invalid.token",
			expected:       nil,
			expectingError: true,
		},
		{
			name:           "Invalid Payload Encoding",
			token:          "header." + base64.RawURLEncoding.EncodeToString([]byte("invalid payload")) + ".signature",
			expected:       nil,
			expectingError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := decodeJWTPayload(tt.token)

			if tt.expectingError && err == nil {
				t.Errorf("Expected an error but got none")
			}

			if !tt.expectingError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectingError && !compareMaps(payload, tt.expected) {
				t.Errorf("Payload mismatch. Expected: %v, Got: %v", tt.expected, payload)
			}
		})
	}
}

func createTestJWT(payload map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + encodedPayload + ".signature"
}

func compareMaps(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for key, valueA := range a {
		if valueB, exists := b[key]; !exists || valueA != valueB {
			return false
		}
	}
	return true
}
