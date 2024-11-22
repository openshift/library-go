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
		name         string
		version      string
		shouldReject bool
		tooOld       bool
		nodes        []*v1.Node
		nodeListErr  error
		errMsg       string
	}{
		// no rejections
		{
			name:         "should not reject when minimum kubelet version is empty",
			version:      "",
			shouldReject: false,
		},
		{
			name:         "should reject when min kubelet version bogus",
			version:      "bogus",
			shouldReject: true,
			nodes: []*v1.Node{
				{
					Status: v1.NodeStatus{
						NodeInfo: v1.NodeSystemInfo{
							KubeletVersion: "v1.30.0",
						},
					},
				},
			},
			errMsg: "failed to parse submitted version bogus No Major.Minor.Patch elements found",
		},
		{
			name:         "should reject when kubelet version is bogus",
			version:      "1.30.0",
			shouldReject: true,
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
			errMsg: "failed to parse node version bogus: No Major.Minor.Patch elements found",
		},
		{
			name:         "should reject when kubelet version is too old",
			version:      "1.30.0",
			shouldReject: true,
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
			errMsg: "kubelet version is outdated: kubelet version is 1.29.0, which is lower than minimumKubeletVersion of 1.30.0",
		},
		{
			name:         "should reject when one kubelet version is too old",
			version:      "1.30.0",
			shouldReject: true,
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
			errMsg: "kubelet version is outdated: kubelet version is 1.29.0, which is lower than minimumKubeletVersion of 1.30.0",
		},
		{
			name:         "should not reject when kubelet version is equal",
			version:      "1.30.0",
			shouldReject: false,
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
			name:         "should reject when min version incomplete",
			version:      "1.30",
			shouldReject: true,
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
			errMsg: "failed to parse submitted version 1.30 No Major.Minor.Patch elements found",
		},
		{
			name:         "should reject when kubelet version incomplete",
			version:      "1.30.0",
			shouldReject: true,
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
			errMsg: "failed to parse node version 1.30: No Major.Minor.Patch elements found",
		},
		{
			name:         "should not reject when kubelet version is new enough",
			version:      "1.30.0",
			shouldReject: false,
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
		shouldStr := "should not be"
		if testCase.shouldReject {
			shouldStr = "should be"
		}
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateMinimumKubeletVersion(testCase.nodes, testCase.version)
			assert.Equal(t, testCase.shouldReject, err != nil, "minimum kubelet version %q %s rejected", testCase.version, shouldStr)

			if testCase.shouldReject {
				assert.Contains(t, err.Error(), testCase.errMsg, "error message should contain %q", testCase.errMsg)
				if strings.Contains(err.Error(), ErrKubeletOutdated.Error()) {
					assert.True(t, errors.Is(err, ErrKubeletOutdated), "error message should be ErrKubeletOutdated")
				}
			}
		})
	}
}
