package crypto

import "testing"

func TestSecurityLevelIsQuantumSafe(t *testing.T) {
	testCases := []struct {
		name     string
		level    SecurityLevel
		expected bool
	}{
		{
			name:     "classical only",
			level:    SecurityLevel{ClassicalBits: 128},
			expected: false,
		},
		{
			name:     "quantum resistant",
			level:    SecurityLevel{ClassicalBits: 128, QuantumBits: 128},
			expected: true,
		},
		{
			name:     "zero value",
			level:    SecurityLevel{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.level.IsQuantumSafe(); got != tc.expected {
				t.Errorf("IsQuantumSafe() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestSecurityLevelCompare(t *testing.T) {
	testCases := []struct {
		name     string
		a        SecurityLevel
		b        SecurityLevel
		expected int
	}{
		{
			name:     "equal levels",
			a:        SecurityLevel{ClassicalBits: 128, QuantumBits: 128},
			b:        SecurityLevel{ClassicalBits: 128, QuantumBits: 128},
			expected: 0,
		},
		{
			name:     "classical bits order classical-only levels",
			a:        SecurityLevel{ClassicalBits: 112},
			b:        SecurityLevel{ClassicalBits: 128},
			expected: -1,
		},
		{
			name:     "quantum level beats stronger classical-only level",
			a:        SecurityLevel{ClassicalBits: 64, QuantumBits: 1},
			b:        SecurityLevel{ClassicalBits: 256},
			expected: 1,
		},
		{
			name:     "quantum bits take precedence over classical bits",
			a:        SecurityLevel{ClassicalBits: 256, QuantumBits: 128},
			b:        SecurityLevel{ClassicalBits: 128, QuantumBits: 192},
			expected: -1,
		},
		{
			name:     "classical bits break tie between equal quantum bits",
			a:        SecurityLevel{ClassicalBits: 128, QuantumBits: 128},
			b:        SecurityLevel{ClassicalBits: 192, QuantumBits: 128},
			expected: -1,
		},
		{
			name:     "zero value loses to everything",
			a:        SecurityLevel{},
			b:        SecurityLevel{ClassicalBits: 1},
			expected: -1,
		},
		{
			name:     "zero value equals zero value",
			a:        SecurityLevel{},
			b:        SecurityLevel{},
			expected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Compare(tc.b); got != tc.expected {
				t.Errorf("Compare() = %d, expected %d", got, tc.expected)
			}
			if got := tc.b.Compare(tc.a); got != -tc.expected {
				t.Errorf("reversed Compare() = %d, expected %d", got, -tc.expected)
			}
		})
	}
}
