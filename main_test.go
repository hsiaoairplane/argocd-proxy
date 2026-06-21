package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

const testSigningKey = "test-signing-key"

func TestParsePolicyCSV(t *testing.T) {
	tests := []struct {
		name                                string
		policyCSV                           string
		expectedUserToObjectPatternMapping  map[string]rbacPolicy
		expectedGroupToObjectPatternMapping map[string]rbacPolicy
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
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{
				"admin@gmail.com": {
					allow: []string{"*"},
				},
				"admin@hotmail.com": {
					allow: []string{"*"},
				},
				"foobar@gmail.com": {
					allow: []string{"alpha1-*", "alpha2-*", "alpha3-*", "alpha4-*"},
				},
			},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{
				"ALPHA READ ONLY": {
					allow: []string{"alpha1-*", "alpha2-*", "alpha3-*", "alpha4-*"},
				},
				"ALPHA READ ONLY_TW": {
					allow: []string{"alpha1-*", "alpha2-*", "alpha3-*", "alpha4-*"},
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
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{
				"admin@gmail.com": {
					allow: []string{"*"},
				},
				"admin@hotmail.com": {
					allow: []string{"*"},
				},
				"barfoo@gmail.com": {
					allow: []string{"beta-*"},
				},
			},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{
				"ALPHA READ ONLY": {
					allow: []string{"alpha1-*", "alpha2-*", "alpha3-*"},
				},
				"ALPHA READ ONLY_TW": {
					allow: []string{"alpha1-*", "alpha2-*", "alpha3-*"},
				},
				"BETA READ ONLY": {
					allow: []string{"beta-*"},
				},
				"BETA READ ONLY_TW": {
					allow: []string{"beta-*"},
				},
			},
		},
		{
			name: "Valid policy CSV with single group but without role",
			policyCSV: `
				g, GAMMA READ ONLY, team-gamma-readonly
			`,
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{
				"GAMMA READ ONLY": {},
			},
		},
		{
			name: "Valid policy CSV with single role but without group",
			policyCSV: `
				p, team-gamma-readonly, applications, get, gamma-*, allow
			`,
			expectedUserToObjectPatternMapping:  map[string]rbacPolicy{},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{},
		},
		{
			name: "Deny effect overrides a broader allow pattern",
			policyCSV: `
				p, team-alpha, applications, get, alpha-*, allow
				p, team-alpha, applications, get, alpha-secret/*, deny
				g, alpha@gmail.com, team-alpha
			`,
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{
				"alpha@gmail.com": {
					allow: []string{"alpha-*"},
					deny:  []string{"alpha-secret/*"},
				},
			},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{},
		},
		{
			name: "Quoted CSV field containing a comma",
			policyCSV: `
				p, team-ldap, applications, get, ldap-*, allow
				g, "CN=Team Alpha,OU=Groups,DC=example,DC=com", team-ldap
			`,
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{
				"CN=Team Alpha,OU=Groups,DC=example,DC=com": {
					allow: []string{"ldap-*"},
				},
			},
		},
		{
			name: "Role-to-role inheritance",
			policyCSV: `
				p, role:admin-base, applications, get, base-*, allow
				g, role:org-admin, role:admin-base
				g, admin@gmail.com, role:org-admin
			`,
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{
				"admin@gmail.com": {
					allow: []string{"base-*"},
				},
			},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{
				"role:org-admin": {
					allow: []string{"base-*"},
				},
			},
		},
		{
			name: "Resource types other than applications are ignored",
			policyCSV: `
				p, team-alpha, clusters, get, https://example.com, allow
				p, team-alpha, applicationsets, get, alpha-*, allow
				p, team-alpha, logs, get, alpha-*, allow
				p, team-alpha, exec, create, alpha-*, allow
				g, alpha@gmail.com, team-alpha
			`,
			expectedUserToObjectPatternMapping: map[string]rbacPolicy{
				"alpha@gmail.com": {},
			},
			expectedGroupToObjectPatternMapping: map[string]rbacPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userToObjectPatternMapping, groupToObjectPatternMapping := parsePolicyCSV(tt.policyCSV)
			if !reflect.DeepEqual(userToObjectPatternMapping, tt.expectedUserToObjectPatternMapping) {
				t.Errorf("Expected user %+v, but got user %+v", tt.expectedUserToObjectPatternMapping, userToObjectPatternMapping)
			}
			if !reflect.DeepEqual(groupToObjectPatternMapping, tt.expectedGroupToObjectPatternMapping) {
				t.Errorf("Expected group %+v, but got group %+v", tt.expectedGroupToObjectPatternMapping, groupToObjectPatternMapping)
			}
		})
	}
}

func TestResolveObjectPatterns(t *testing.T) {
	tests := []struct {
		name                        string
		email                       string
		groups                      []string
		userToObjectPatternMapping  map[string]rbacPolicy
		groupToObjectPatternMapping map[string]rbacPolicy
		expectedAllow               map[string]struct{}
		expectedDeny                []string
	}{
		{
			name:   "User with direct patterns",
			email:  "user1@example.com",
			groups: []string{},
			userToObjectPatternMapping: map[string]rbacPolicy{
				"user1@example.com": {allow: []string{"pattern1", "pattern2"}},
			},
			groupToObjectPatternMapping: map[string]rbacPolicy{},
			expectedAllow: map[string]struct{}{
				"pattern1": {},
				"pattern2": {},
			},
		},
		{
			name:   "Group with patterns",
			email:  "user2@example.com",
			groups: []string{"group1"},
			userToObjectPatternMapping: map[string]rbacPolicy{
				"user2@example.com": {},
			},
			groupToObjectPatternMapping: map[string]rbacPolicy{
				"group1": {allow: []string{"pattern3", "pattern4"}},
			},
			expectedAllow: map[string]struct{}{
				"pattern3": {},
				"pattern4": {},
			},
		},
		{
			name:   "User and groups with patterns",
			email:  "user3@example.com",
			groups: []string{"group1", "group2"},
			userToObjectPatternMapping: map[string]rbacPolicy{
				"user3@example.com": {allow: []string{"pattern5"}},
			},
			groupToObjectPatternMapping: map[string]rbacPolicy{
				"group1": {allow: []string{"pattern6"}},
				"group2": {allow: []string{"pattern7"}},
			},
			expectedAllow: map[string]struct{}{
				"pattern5": {},
				"pattern6": {},
				"pattern7": {},
			},
		},
		{
			name:                        "No patterns for user or groups",
			email:                       "user4@example.com",
			groups:                      []string{"group3"},
			userToObjectPatternMapping:  map[string]rbacPolicy{},
			groupToObjectPatternMapping: map[string]rbacPolicy{},
			expectedAllow:               map[string]struct{}{},
		},
		{
			name:   "Deny patterns are collected from both user and group policies",
			email:  "user5@example.com",
			groups: []string{"group1"},
			userToObjectPatternMapping: map[string]rbacPolicy{
				"user5@example.com": {allow: []string{"pattern1"}, deny: []string{"pattern1-secret/*"}},
			},
			groupToObjectPatternMapping: map[string]rbacPolicy{
				"group1": {allow: []string{"pattern2"}, deny: []string{"pattern2-secret/*"}},
			},
			expectedAllow: map[string]struct{}{
				"pattern1": {},
				"pattern2": {},
			},
			expectedDeny: []string{"pattern1-secret/*", "pattern2-secret/*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, deny := resolveObjectPatterns(tt.email, tt.groups, tt.userToObjectPatternMapping, tt.groupToObjectPatternMapping)

			if !reflect.DeepEqual(allow, tt.expectedAllow) {
				t.Errorf("resolveObjectPatterns() allow = %v, want %v", allow, tt.expectedAllow)
			}
			if !reflect.DeepEqual(deny, tt.expectedDeny) {
				t.Errorf("resolveObjectPatterns() deny = %v, want %v", deny, tt.expectedDeny)
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

func TestVerifyAndDecodeJWT(t *testing.T) {
	signingKey := []byte(testSigningKey)

	tests := []struct {
		name           string
		token          string
		signingKey     []byte
		expected       map[string]interface{}
		expectingError bool
	}{
		{
			name:           "Valid signed token",
			token:          createTestJWT(map[string]interface{}{"email": "test@example.com", "role": "admin"}),
			signingKey:     signingKey,
			expected:       map[string]interface{}{"email": "test@example.com", "role": "admin"},
			expectingError: false,
		},
		{
			name:           "Wrong signing key is rejected",
			token:          createTestJWT(map[string]interface{}{"email": "test@example.com"}),
			signingKey:     []byte("a-different-key"),
			expectingError: true,
		},
		{
			name:           "No signing key configured",
			token:          createTestJWT(map[string]interface{}{"email": "test@example.com"}),
			signingKey:     nil,
			expectingError: true,
		},
		{
			name:           "alg=none token is rejected",
			token:          unsignedNoneAlgToken(map[string]interface{}{"email": "attacker@example.com", "role": "admin"}),
			signingKey:     signingKey,
			expectingError: true,
		},
		{
			name:           "Tampered payload is rejected",
			token:          tamperPayload(createTestJWT(map[string]interface{}{"email": "test@example.com"})),
			signingKey:     signingKey,
			expectingError: true,
		},
		{
			name:           "Malformed token",
			token:          "not-a-jwt",
			signingKey:     signingKey,
			expectingError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := verifyAndDecodeJWT(tt.token, tt.signingKey)

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

// createTestJWT signs payload with testSigningKey using HS256, mirroring how
// ArgoCD signs its own session tokens.
func createTestJWT(payload map[string]interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(payload))
	signed, err := token.SignedString([]byte(testSigningKey))
	if err != nil {
		panic(err)
	}
	return signed
}

// unsignedNoneAlgToken builds a token asserting alg=none with an empty
// signature, the classic JWT algorithm-confusion forgery.
func unsignedNoneAlgToken(payload map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + encodedPayload + "."
}

// tamperPayload swaps in a different payload while keeping the original
// header and signature, simulating an attacker editing claims in place.
func tamperPayload(token string) string {
	parts := strings.Split(token, ".")
	tampered := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"attacker@example.com"}`))
	return parts[0] + "." + tampered + "." + parts[2]
}

func TestFilterRawByClusterAndNamespace(t *testing.T) {
	makeApp := func(server, name, namespace string) []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"spec": map[string]interface{}{
				"destination": map[string]interface{}{
					"server":    server,
					"name":      name,
					"namespace": namespace,
				},
			},
		})
		return b
	}

	appA := makeApp("https://cluster-a.example.com", "cluster-a", "ns-1")
	appB := makeApp("https://cluster-b.example.com", "cluster-b", "ns-2")
	appC := makeApp("https://cluster-a.example.com", "cluster-a", "ns-2")
	appD := makeApp("", "cluster-b", "ns-1")

	tests := []struct {
		name      string
		items     [][]byte
		cluster   string
		namespace string
		expected  [][]byte
	}{
		{
			name:      "Filter by cluster server URL",
			items:     [][]byte{appA, appB, appC},
			cluster:   "https://cluster-a.example.com",
			namespace: "",
			expected:  [][]byte{appA, appC},
		},
		{
			name:      "Filter by cluster name",
			items:     [][]byte{appA, appB, appD},
			cluster:   "cluster-b",
			namespace: "",
			expected:  [][]byte{appB, appD},
		},
		{
			name:      "Filter by namespace",
			items:     [][]byte{appA, appB, appC},
			cluster:   "",
			namespace: "ns-2",
			expected:  [][]byte{appB, appC},
		},
		{
			name:      "Filter by cluster and namespace",
			items:     [][]byte{appA, appB, appC},
			cluster:   "https://cluster-a.example.com",
			namespace: "ns-2",
			expected:  [][]byte{appC},
		},
		{
			name:      "No match returns empty list",
			items:     [][]byte{appA, appB, appC},
			cluster:   "https://no-cluster.example.com",
			namespace: "",
			expected:  [][]byte{},
		},
		{
			name:      "Empty items list",
			items:     [][]byte{},
			cluster:   "https://cluster-a.example.com",
			namespace: "ns-1",
			expected:  [][]byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterRawByClusterAndNamespace(tt.items, tt.cluster, tt.namespace)
			if len(result) != len(tt.expected) {
				t.Errorf("filterRawByClusterAndNamespace() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, item := range result {
				if !bytes.Equal(item, tt.expected[i]) {
					t.Errorf("filterRawByClusterAndNamespace()[%d] = %s, want %s", i, item, tt.expected[i])
				}
			}
		})
	}
}

func TestMatchesObjectPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		object   string
		expected bool
	}{
		{name: "Bare wildcard matches any object", pattern: "*", object: "myproj/myapp", expected: true},
		{name: "Project wildcard matches app in project", pattern: "myproj/*", object: "myproj/myapp", expected: true},
		{name: "Project wildcard does not match other project", pattern: "myproj/*", object: "otherproj/myapp", expected: false},
		{name: "Exact match", pattern: "myproj/myapp", object: "myproj/myapp", expected: true},
		{name: "Prefix glob within project", pattern: "myproj/alpha-*", object: "myproj/alpha-1", expected: true},
		{name: "Prefix glob does not match other prefix", pattern: "myproj/alpha-*", object: "myproj/beta-1", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := matchesObjectPattern(tt.pattern, tt.object); result != tt.expected {
				t.Errorf("matchesObjectPattern(%q, %q) = %v, want %v", tt.pattern, tt.object, result, tt.expected)
			}
		})
	}
}

func TestExcludeDenied(t *testing.T) {
	makeApp := func(project, name string) []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{"name": name},
			"spec":     map[string]interface{}{"project": project},
		})
		return b
	}

	appA := makeApp("myproj", "alpha-1")
	appB := makeApp("myproj", "alpha-secret")
	appC := makeApp("myproj", "beta-1")

	tests := []struct {
		name         string
		items        [][]byte
		denyPatterns []string
		expected     [][]byte
	}{
		{
			name:         "Narrow deny within a broad allow",
			items:        [][]byte{appA, appB, appC},
			denyPatterns: []string{"myproj/alpha-secret"},
			expected:     [][]byte{appA, appC},
		},
		{
			name:         "Deny all via bare wildcard",
			items:        [][]byte{appA, appB, appC},
			denyPatterns: []string{"*"},
			expected:     [][]byte{},
		},
		{
			name:         "No deny patterns",
			items:        [][]byte{appA, appB},
			denyPatterns: nil,
			expected:     [][]byte{appA, appB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := excludeDenied(tt.items, tt.denyPatterns)
			if len(result) != len(tt.expected) {
				t.Errorf("excludeDenied() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, item := range result {
				if !bytes.Equal(item, tt.expected[i]) {
					t.Errorf("excludeDenied()[%d] = %s, want %s", i, item, tt.expected[i])
				}
			}
		})
	}
}

func TestResolveReachableRoles(t *testing.T) {
	edges := map[string][]string{
		"admin@gmail.com": {"role:org-admin"},
		"role:org-admin":  {"role:admin-base", "role:org-admin"}, // self-edge to verify cycle safety
	}

	result := resolveReachableRoles("admin@gmail.com", edges)
	expected := []string{"role:org-admin", "role:admin-base"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("resolveReachableRoles() = %v, want %v", result, expected)
	}
}

func TestWriteApplicationList(t *testing.T) {
	tests := []struct {
		name     string
		items    [][]byte
		expected string
	}{
		{
			name:     "Empty list",
			items:    [][]byte{},
			expected: `{"items":[]}`,
		},
		{
			name:     "Single item",
			items:    [][]byte{[]byte(`{"metadata":{"name":"a"}}`)},
			expected: `{"items":[{"metadata":{"name":"a"}}]}`,
		},
		{
			name:     "Multiple items are comma-joined",
			items:    [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"b"}}`)},
			expected: `{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeApplicationList(rec, tt.items)

			if got := rec.Body.String(); got != tt.expected {
				t.Errorf("writeApplicationList() = %s, want %s", got, tt.expected)
			}

			// The envelope must be valid JSON and preserve every item verbatim
			// (no re-marshaling), which is the whole point of the optimization.
			var decoded struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("writeApplicationList() produced invalid JSON: %v", err)
			}
			if len(decoded.Items) != len(tt.items) {
				t.Fatalf("decoded %d items, want %d", len(decoded.Items), len(tt.items))
			}
			for i, raw := range decoded.Items {
				if !bytes.Equal(raw, tt.items[i]) {
					t.Errorf("item[%d] = %s, want %s (bytes must be preserved)", i, raw, tt.items[i])
				}
			}
		})
	}
}

func TestExtractGroups(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]interface{}
		expected []string
	}{
		{
			name:     "Groups present as JSON array",
			payload:  map[string]interface{}{"groups": []interface{}{"group1", "group2"}},
			expected: []string{"group1", "group2"},
		},
		{
			name:     "Groups missing",
			payload:  map[string]interface{}{"email": "user@example.com"},
			expected: nil,
		},
		{
			name:     "Groups with non-string elements are skipped",
			payload:  map[string]interface{}{"groups": []interface{}{"group1", 42, "group2"}},
			expected: []string{"group1", "group2"},
		},
		{
			name:     "Empty groups array",
			payload:  map[string]interface{}{"groups": []interface{}{}},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGroups(tt.payload)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractGroups() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractGroupsFromDecodedJWT(t *testing.T) {
	// Guard against the regression where a JSON array claim was asserted as
	// []string directly, which always fails and silently drops all groups.
	token := createTestJWT(map[string]interface{}{
		"email":  "user@example.com",
		"groups": []string{"team-a", "team-b"},
	})

	payload, err := verifyAndDecodeJWT(token, []byte(testSigningKey))
	if err != nil {
		t.Fatalf("verifyAndDecodeJWT() unexpected error: %v", err)
	}

	groups := extractGroups(payload)
	expected := []string{"team-a", "team-b"}
	if !reflect.DeepEqual(groups, expected) {
		t.Errorf("extractGroups() = %v, want %v", groups, expected)
	}
}

func TestShouldInterceptListRequest(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		expected bool
	}{
		{"GET list endpoint is intercepted", http.MethodGet, "/api/v1/applications", true},
		{"single application is not intercepted", http.MethodGet, "/api/v1/applications/myapp", false},
		{"applicationsets is not intercepted", http.MethodGet, "/api/v1/applicationsets", false},
		{"resource subpath is not intercepted", http.MethodGet, "/api/v1/applications/myapp/resource-tree", false},
		{"non-GET list endpoint is not intercepted", http.MethodPost, "/api/v1/applications", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if got := shouldInterceptListRequest(req); got != tt.expected {
				t.Errorf("shouldInterceptListRequest(%s %s) = %v, want %v", tt.method, tt.path, got, tt.expected)
			}
		})
	}
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

func TestComputeETag(t *testing.T) {
	a := [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"b"}}`)}

	e := computeETag(a)
	if computeETag(a) != e {
		t.Error("etag not stable for identical items")
	}
	// Different content -> different etag.
	b := [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"c"}}`)}
	if computeETag(b) == e {
		t.Error("etag collided for different items")
	}
	// Must be a quoted strong ETag.
	if len(e) < 2 || e[0] != '"' || e[len(e)-1] != '"' {
		t.Errorf("etag must be quoted, got %s", e)
	}
	// Empty items still produce a stable etag.
	if computeETag(nil) != computeETag([][]byte{}) {
		t.Error("empty etag not stable")
	}
}

func TestServeCachedList(t *testing.T) {
	items := [][]byte{[]byte(`{"metadata":{"name":"a"}}`), []byte(`{"metadata":{"name":"b"}}`)}

	// First request: 200 with ETag + full body.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()
	serveCachedList(rec, req, items)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	et := rec.Header().Get("ETag")
	if et == "" {
		t.Fatal("missing ETag")
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("missing Content-Type")
	}
	if got, want := rec.Body.String(), `{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}

	// Conditional request with matching ETag: 304, empty body, ETag still present.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req2.Header.Set("If-None-Match", et)
	rec2 := httptest.NewRecorder()
	serveCachedList(rec2, req2, items)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 body must be empty, got %d bytes", rec2.Body.Len())
	}
	if rec2.Header().Get("ETag") != et {
		t.Errorf("304 should still carry the ETag")
	}

	// Stale If-None-Match -> 200 with body.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	req3.Header.Set("If-None-Match", `"stale"`)
	rec3 := httptest.NewRecorder()
	serveCachedList(rec3, req3, items)
	if rec3.Code != http.StatusOK {
		t.Errorf("stale If-None-Match should be 200, got %d", rec3.Code)
	}
}
