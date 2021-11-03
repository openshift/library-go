package leaderelection

import (
	"reflect"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLeaderElectionSNOConfig(t *testing.T) {
	testCases := []struct {
		desc           string
		inputConfig    configv1.LeaderElection
		expectedConfig configv1.LeaderElection
	}{
		{
			desc: "should not alter disable flag when true",
			inputConfig: configv1.LeaderElection{
				Disable: true,
			},
			expectedConfig: configv1.LeaderElection{
				Disable:       true,
				LeaseDuration: metav1.Duration{Duration: 270 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 240 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 60 * time.Second},
			},
		},
		{
			desc: "should not alter disable flag when false",
			inputConfig: configv1.LeaderElection{
				Disable: false,
			},
			expectedConfig: configv1.LeaderElection{
				Disable:       false,
				LeaseDuration: metav1.Duration{Duration: 270 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 240 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 60 * time.Second},
			},
		},
		{
			desc:        "should change durations when none are provided",
			inputConfig: configv1.LeaderElection{},
			expectedConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 270 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 240 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 60 * time.Second},
			},
		},
		{
			desc: "should change durations for sno configs",
			inputConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expectedConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 270 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 240 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 60 * time.Second},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			resultConfig := LeaderElectionSNOConfig(tc.inputConfig)
			if !reflect.DeepEqual(tc.expectedConfig, resultConfig) {
				t.Errorf("expected %#v, got %#v", tc.expectedConfig, resultConfig)
			}
		})
	}
}

func TestLeaderElectionDefaulting(t *testing.T) {
	testCases := []struct {
		desc             string
		defaultNamespace string
		defaultName      string
		inputConfig      configv1.LeaderElection
		expectedConfig   configv1.LeaderElection
	}{
		{
			desc: "should not alter disable flag when true",
			inputConfig: configv1.LeaderElection{
				Disable: true,
			},
			expectedConfig: configv1.LeaderElection{
				Disable:       true,
				LeaseDuration: metav1.Duration{Duration: 137 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 107 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 26 * time.Second},
			},
		},
		{
			desc: "should not alter disable flag when false",
			inputConfig: configv1.LeaderElection{
				Disable: false,
			},
			expectedConfig: configv1.LeaderElection{
				Disable:       false,
				LeaseDuration: metav1.Duration{Duration: 137 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 107 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 26 * time.Second},
			},
		},
		{
			desc:        "should change durations when none are provided",
			inputConfig: configv1.LeaderElection{},
			expectedConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 137 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 107 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 26 * time.Second},
			},
		},
		{
			desc:             "should use default name and namespace when none is provided",
			inputConfig:      configv1.LeaderElection{},
			defaultName:      "new-default-name",
			defaultNamespace: "new-default-namespace",
			expectedConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 137 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 107 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 26 * time.Second},
				Name:          "new-default-name",
				Namespace:     "new-default-namespace",
			},
		},
		{
			desc: "should not alter durations when values are provided",
			inputConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expectedConfig: configv1.LeaderElection{
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
		},
		{
			desc:             "should not alter when durations, name and namespace are provided",
			defaultName:      "new-default-name",
			defaultNamespace: "new-default-namespace",
			inputConfig: configv1.LeaderElection{
				Name:          "original-name",
				Namespace:     "original-namespace",
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
			expectedConfig: configv1.LeaderElection{
				Name:          "original-name",
				Namespace:     "original-namespace",
				LeaseDuration: metav1.Duration{Duration: 60 * time.Second},
				RenewDeadline: metav1.Duration{Duration: 40 * time.Second},
				RetryPeriod:   metav1.Duration{Duration: 20 * time.Second},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			resultConfig := LeaderElectionDefaulting(tc.inputConfig, tc.defaultNamespace, tc.defaultName)

			// When testing in clusters, namespace is read from /var/run/secrets/kubernetes.io/serviceaccount/namespace in LeaderElectionDefaulting if none is provided.
			// We configure expectedConfig.Namespace to equal resultConfig.Namespace if no default or input namespace is provided
			// so we use the dynamic namespace read in from the environment
			if tc.defaultNamespace == "" && tc.inputConfig.Namespace == "" {
				tc.expectedConfig.Namespace = resultConfig.Namespace
			}

			if !reflect.DeepEqual(tc.expectedConfig, resultConfig) {
				t.Errorf("expected %#v, got %#v", tc.expectedConfig, resultConfig)
			}
		})
	}
}
