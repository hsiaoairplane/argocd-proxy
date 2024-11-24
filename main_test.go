package main

import (
	"reflect"
	"testing"
)

func TestParsePolicyCSV(t *testing.T) {
	tests := []struct {
		name      string
		policyCSV string
		expected  map[string][]string
	}{
		{
			name: "Valid policy CSV with multiple teams",
			policyCSV: `
				p, my-org:team-alpha, applications, get, alpha-*/*, allow
				p, my-org:team-beta, applications, get, beta-*/*, allow
				p, my-org:team-gamma, applications, get, gamma-*/*, allow
			`,
			expected: map[string][]string{
				"my-org:team-alpha": {"alpha-*/*"},
				"my-org:team-beta":  {"beta-*/*"},
				"my-org:team-gamma": {"gamma-*/*"},
			},
		},
		{
			name: "Policy CSV with comments and empty lines",
			policyCSV: `
				# This is a comment
				p, my-org:team-alpha, applications, get, alpha-*/*, allow

				# Another comment
				p, my-org:team-beta, applications, get, beta-*/*, allow

			`,
			expected: map[string][]string{
				"my-org:team-alpha": {"alpha-*/*"},
				"my-org:team-beta":  {"beta-*/*"},
			},
		},
		{
			name: "Policy CSV with no valid policies",
			policyCSV: `
				# This is a comment
				g, my-org:team-alpha, role:read-only
			`,
			expected: map[string][]string{},
		},
		{
			name: "Policy CSV with multiple policies for one team",
			policyCSV: `
				p, my-org:team-alpha, applications, get, alpha-*/*, allow
				p, my-org:team-alpha, applications, get, alpha-app1/*, allow
			`,
			expected: map[string][]string{
				"my-org:team-alpha": {"alpha-*/*", "alpha-app1/*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePolicyCSV(tt.policyCSV)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}
