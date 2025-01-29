package node

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateConfigNodeForMinimumKubeletVersion(t *testing.T) {
	testCases := []struct {
		name        string
		version     string
		nodes       []*v1.Node
		nodeListErr error
		expectedErr error
	}{
		// no rejections
		{
			name:    "should not reject when minimum kubelet version is empty",
			version: "",
		},
		{
			name:    "should reject when min kubelet version bogus",
			version: "bogus",
			nodes: []*v1.Node{
				{
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.30.0",
						},
					},
				},
			},
			expectedErr: errors.New("failed to parse submitted version bogus No Major.Minor.Patch elements found"),
		},
		{
			name:    "should reject when kubelet version is bogus",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "bogus",
						},
					},
				},
			},
			expectedErr: errors.New("failed to parse node version bogus: No Major.Minor.Patch elements found"),
		},
		{
			name:    "should reject when kubelet version is too old",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.29.0",
						},
					},
				},
			},
			expectedErr: errors.New("kubelet version is outdated: kubelet version is 1.29.0, which is lower than minimumKubeletVersion of 1.30.0"),
		},
		{
			name:    "should reject when one kubelet version is too old",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.30.0",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node2",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.29.0",
						},
					},
				},
			},
			expectedErr: errors.New("kubelet version is outdated: kubelet version is 1.29.0, which is lower than minimumKubeletVersion of 1.30.0"),
		},
		{
			name:    "should not reject when kubelet version is equal",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.30.0",
						},
					},
				},
			},
		},
		{
			name:    "should reject when min version incomplete",
			version: "1.30",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.30.0",
						},
					},
				},
			},
			expectedErr: errors.New("failed to parse submitted version 1.30 No Major.Minor.Patch elements found"),
		},
		{
			name:    "should reject when kubelet version incomplete",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "1.30",
						},
					},
				},
			},
			expectedErr: errors.New("failed to parse node version 1.30: No Major.Minor.Patch elements found"),
		},
		{
			name:    "should not reject when kubelet version is new enough",
			version: "1.30.0",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.31.0",
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateMinimumKubeletVersion(testCase.nodes, testCase.version)

			if err == nil && testCase.expectedErr != nil {
				t.Fatal("expected to get an error")
			}
			if err != nil && testCase.expectedErr == nil {
				t.Fatal(err) // unexpected error
			}
			if err != nil && testCase.expectedErr != nil {
				if err.Error() != testCase.expectedErr.Error() {
					t.Fatalf("unexpected error = %v, expected = %v", err, testCase.expectedErr)
				}
				if strings.Contains(err.Error(), ErrKubeletOutdated.Error()) {
					assert.True(t, errors.Is(err, ErrKubeletOutdated), "error message should be ErrKubeletOutdated")
				}
			}
		})
	}
}
