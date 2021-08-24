package proc

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseProcForZombies(t *testing.T) {
	for _, tc := range []struct {
		testdir     string
		shouldError bool
		expected    []int
	}{
		{
			testdir:  "proc_success_1",
			expected: []int{10, 215, 423, 809, 1037, 2096, 4010},
		},
		{
			testdir:  "proc_success_2",
			expected: nil,
		},
		{
			testdir:     "proc_fail",
			shouldError: true,
		},
	} {
		res, err := parseProcForZombies(filepath.Join("testdata", tc.testdir))
		if tc.shouldError {
			assert.NotNil(t, err)
			assert.Empty(t, res)
		} else {
			assert.Nil(t, err)
			sort.Ints(res)
			assert.Equal(t, tc.expected, res)
		}
	}
}
