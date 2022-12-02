package defaulting

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/utils/pointer"

	v1 "github.com/openshift/api/route/v1"
)

func TestSetDefaults_RouteSpec(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original v1.RouteSpec
		expected v1.RouteSpec
	}{
		{
			name: "nonempty wildcardpolicy preserved",
			original: v1.RouteSpec{
				WildcardPolicy: "nonempty",
			},
			expected: v1.RouteSpec{
				WildcardPolicy: "nonempty",
			},
		},
		{
			name: "empty wildcardpolicy defaulted",
			original: v1.RouteSpec{
				WildcardPolicy: "",
			},
			expected: v1.RouteSpec{
				WildcardPolicy: v1.WildcardPolicyNone,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.original.DeepCopy()
			SetDefaults_RouteSpec(actual)
			if !apiequality.Semantic.DeepEqual(&tc.expected, actual) {
				t.Errorf("expected vs got:\n%s", cmp.Diff(&tc.expected, actual))
			}
		})
	}
}

func TestSetDefaults_RouteTargetReference(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original v1.RouteTargetReference
		expected v1.RouteTargetReference
	}{
		{
			name: "nonempty kind and non-null weight preserved",
			original: v1.RouteTargetReference{
				Kind:   "nonempty",
				Weight: pointer.Int32(7),
			},
			expected: v1.RouteTargetReference{
				Kind:   "nonempty",
				Weight: pointer.Int32(7),
			},
		},
		{
			name: "empty kind defaulted and non-null weight preserved",
			original: v1.RouteTargetReference{
				Kind:   "",
				Weight: pointer.Int32(7),
			},
			expected: v1.RouteTargetReference{
				Kind:   "Service",
				Weight: pointer.Int32(7),
			},
		},
		{
			name: "empty kind and null weight defaulted",
			original: v1.RouteTargetReference{
				Kind:   "",
				Weight: nil,
			},
			expected: v1.RouteTargetReference{
				Kind:   "Service",
				Weight: pointer.Int32(100),
			},
		},
		{
			name: "nonempty kind preserved and null weight defaulted",
			original: v1.RouteTargetReference{
				Kind:   "nonempty",
				Weight: nil,
			},
			expected: v1.RouteTargetReference{
				Kind:   "nonempty",
				Weight: pointer.Int32(100),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.original.DeepCopy()
			SetDefaults_RouteTargetReference(actual)
			if !apiequality.Semantic.DeepEqual(&tc.expected, actual) {
				t.Errorf("expected vs got:\n%s", cmp.Diff(&tc.expected, actual))
			}
		})
	}
}

func TestSetDefaults_TLSConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original v1.TLSConfig
		expected v1.TLSConfig
	}{
		{
			name: "reencrypt termination normalized",
			original: v1.TLSConfig{
				Termination: "Reencrypt",
			},
			expected: v1.TLSConfig{
				Termination: v1.TLSTerminationReencrypt,
			},
		},
		{
			name: "edge termination normalized",
			original: v1.TLSConfig{
				Termination: "Edge",
			},
			expected: v1.TLSConfig{
				Termination: v1.TLSTerminationEdge,
			},
		},
		{
			name: "passthrough termination normalized",
			original: v1.TLSConfig{
				Termination: "Passthrough",
			},
			expected: v1.TLSConfig{
				Termination: v1.TLSTerminationPassthrough,
			},
		},
		{
			name: "empty termination defaulted to edge with empty destination ca certificate",
			original: v1.TLSConfig{
				Termination: "",
			},
			expected: v1.TLSConfig{
				Termination: v1.TLSTerminationEdge,
			},
		},
		{
			name: "empty termination not defaulted with nonempty destination ca certificate",
			original: v1.TLSConfig{
				Termination:              "",
				DestinationCACertificate: "nonempty",
			},
			expected: v1.TLSConfig{
				Termination:              "",
				DestinationCACertificate: "nonempty",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.original.DeepCopy()
			SetDefaults_TLSConfig(actual)
			if !apiequality.Semantic.DeepEqual(&tc.expected, actual) {
				t.Errorf("expected vs got:\n%s", cmp.Diff(&tc.expected, actual))
			}
		})
	}
}

func TestSetDefaults_RouteIngress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original v1.RouteIngress
		expected v1.RouteIngress
	}{
		{
			name: "nonempty wildcardpolicy preserved",
			original: v1.RouteIngress{
				WildcardPolicy: "nonempty",
			},
			expected: v1.RouteIngress{
				WildcardPolicy: "nonempty",
			},
		},
		{
			name: "empty wildcardpolicy defaulted",
			original: v1.RouteIngress{
				WildcardPolicy: "",
			},
			expected: v1.RouteIngress{
				WildcardPolicy: v1.WildcardPolicyNone,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.original.DeepCopy()
			SetDefaults_RouteIngress(actual)
			if !apiequality.Semantic.DeepEqual(&tc.expected, actual) {
				t.Errorf("expected vs got:\n%s", cmp.Diff(&tc.expected, actual))
			}
		})
	}
}
