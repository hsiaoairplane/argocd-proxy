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
			name: "Valid policy CSV with single team ALPHA READ ONLY",
			policyCSV: `
				g, admin@gmail.com, role:admin
				g, admin@hotmail.com, role:admin
				p, team-alpha-readonly, applications, get, alpha1-*, allow
				p, team-alpha-readonly, applications, get, alpha2-*/*, allow
				p, team-alpha-readonly, applications, get, alpha3-*, allow
				p, team-alpha-readonly, applications, get, alpha4-*/*, allow
				g, ALPHA READ ONLY, team-alpha-readonly
				g, foobar@gmail.com, team-alpha-readonly
			`,
			expected: map[string][]string{
				"admin@gmail.com": {
					"*",
				},
				"admin@hotmail.com": {
					"*",
				},
				"ALPHA READ ONLY": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
					"alpha4-*",
				},
				"foobar@gmail.com": {
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
				g, admin@hotmail.com, role:admin
				p, team-alpha-readonly, applications, get, alpha1-*, allow
				p, team-alpha-readonly, applications, get, alpha2-*, allow
				p, team-alpha-readonly, applications, get, alpha3-*/*, allow
				g, ALPHA READ ONLY, team-alpha-readonly
				p, team-beta-readonly, applications, get, beta-*/*, allow
				g, BETA READ ONLY, team-beta-readonly
				g, barfoo@gmail.com, team-beta-readonly
			`,
			expected: map[string][]string{
				"admin@gmail.com": {
					"*",
				},
				"admin@hotmail.com": {
					"*",
				},
				"ALPHA READ ONLY": {
					"alpha1-*",
					"alpha2-*",
					"alpha3-*",
				},
				"BETA READ ONLY": {
					"beta-*",
				},
				"barfoo@gmail.com": {
					"beta-*",
				},
			},
		},
		{
			name: "Valid policy CSV with single group but without role",
			policyCSV: `
				g, GAMMA READ ONLY, team-gamma-readonly
			`,
			expected: map[string][]string{
				"GAMMA READ ONLY": {},
			},
		},
		{
			name: "Valid policy CSV with single role but without group",
			policyCSV: `
				p, team-gamma-readonly, applications, get, gamma-*, allow
			`,
			expected: map[string][]string{},
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
