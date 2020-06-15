package oauth

import (
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type testLister struct {
	lister configlistersv1.OAuthLister
}

func (l testLister) OAuthLister() configlistersv1.OAuthLister {
	return l.lister
}

func (l testLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l testLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

func TestObserveAccessTokenMaxAgeSeconds(t *testing.T) {
	tests := []struct {
		name                     string
		config                   *configv1.OAuth
		previouslyObservedConfig map[string]interface{}
		expected                 map[string]interface{}
		errors                   []error
	}{
		{
			name:     "no oauth config and no previous config",
			expected: map[string]interface{}{},
			errors:   []error{fmt.Errorf("NotFound: token max age seconds")},
		},
		{
			name: "no oauth config",
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds":     float64(172800),
						"accessTokenInactivityTimeout": float64(300),
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds": float64(172800),
					},
				},
			},
			errors: []error{fmt.Errorf("NotFound: token max age seconds")},
		},
		{
			name: "must return configured value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenMaxAgeSeconds: 172800,
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds": float64(172800),
					},
				},
			},
		},
		{
			name: "default value must be returned",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds": float64(86400),
					},
				},
			},
		},
		{
			name: "invalid existing config",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenMaxAgeSeconds: 172800,
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": "foo",
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenMaxAgeSeconds": float64(172800),
					},
				},
			},
			errors: []error{fmt.Errorf("token max age parse error")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.config != nil {
				if err := indexer.Add(tt.config); err != nil {
					t.Fatal(err)
				}
			}

			lister := testLister{lister: configlistersv1.NewOAuthLister(indexer)}

			got, errs := ObserveAccessTokenMaxAgeSeconds(lister, events.NewInMemoryRecorder(t.Name()), tt.previouslyObservedConfig)
			if len(errs) != len(tt.errors) {
				t.Errorf("Expected 0 errors, got %v.", len(errs))
			}
			if !equality.Semantic.DeepEqual(tt.expected, got) {
				t.Errorf("result does not match expected config: %s", diff.ObjectDiff(tt.expected, got))
			}
		})
	}

	existingConfig := map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"tokenConfig": map[string]interface{}{
				"accessTokenMaxAgeSeconds": float64(86400),
			},
		},
	}

	got, errs := ObserveAccessTokenMaxAgeSeconds(invalidLister{}, events.NewInMemoryRecorder("fakeRecorder"), existingConfig)

	// There must be only one error asserting the lister type.
	if len(errs) != 1 {
		t.Errorf("expected 1 error. got %d errors", len(errs))
	}

	if !equality.Semantic.DeepEqual(got, existingConfig) {
		t.Errorf("result does not match expected config: %s", diff.ObjectDiff(existingConfig, got))
	}
}

func TestObserveAccessTokenInactivityTimeout(t *testing.T) {
	tests := []struct {
		name                     string
		config                   *configv1.OAuth
		previouslyObservedConfig map[string]interface{}
		expected                 map[string]interface{}
		errors                   []error
	}{
		{
			name:     "no oauth config and no previous config",
			expected: map[string]interface{}{},
			errors:   []error{fmt.Errorf("NotFound: token inactivity timeout seconds")},
		},
		{
			name: "no oauth config with invalid previous config",
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": "foo",
			},
			expected: map[string]interface{}{},
			errors:   []error{fmt.Errorf("NotFound: token inactivity timeout seconds")},
		},
		{
			name: "no oauth config with nil previous config",
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": nil,
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": nil,
					},
				},
			},
			errors: []error{fmt.Errorf("NotFound: token inactivity timeout seconds")},
		},
		{
			name: "no oauth config",
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "5m0.5s",
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "5m0.5s",
					},
				},
			},
			errors: []error{fmt.Errorf("NotFound: token inactivity timeout seconds")},
		},
		{
			name: "must return configured value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenInactivityTimeout: &metav1.Duration{Duration: 500 * time.Second},
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "8m20s",
					},
				},
			},
		},
		{
			name: "must return configured value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenInactivityTimeout: &metav1.Duration{Duration: 500 * time.Second},
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": "foo",
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "8m20s",
					},
				},
			},
			errors: []error{fmt.Errorf("token inactivity timeout parse error")},
		},
		{
			name: "must return configured value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenInactivityTimeout: &metav1.Duration{Duration: 500 * time.Second},
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": nil,
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "8m20s",
					},
				},
			},
			errors: []error{fmt.Errorf("token inactivity timeout parse error")},
		},
		{
			name: "must return configured value",
			config: &configv1.OAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: configv1.OAuthSpec{
					TokenConfig: configv1.TokenConfig{
						AccessTokenInactivityTimeout: &metav1.Duration{Duration: 500 * time.Second},
					},
				},
			},
			previouslyObservedConfig: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "5m0s",
					},
				},
			},
			expected: map[string]interface{}{
				"oauthConfig": map[string]interface{}{
					"tokenConfig": map[string]interface{}{
						"accessTokenInactivityTimeout": "8m20s",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.config != nil {
				if err := indexer.Add(tt.config); err != nil {
					t.Fatal(err)
				}
			}

			lister := testLister{lister: configlistersv1.NewOAuthLister(indexer)}

			got, errs := ObserveAccessTokenInactivityTimeout(lister, events.NewInMemoryRecorder(t.Name()), tt.previouslyObservedConfig)
			if len(errs) != len(tt.errors) {
				t.Errorf("Expected %d errors, got %d.", len(tt.errors), errs)
			}
			if !equality.Semantic.DeepEqual(tt.expected, got) {
				t.Errorf("result does not match expected config: %s", diff.ObjectDiff(tt.expected, got))
			}
		})
	}

	existingConfig := map[string]interface{}{
		"oauthConfig": map[string]interface{}{
			"tokenConfig": map[string]interface{}{
				"accessTokenInactivityTimeout": float64(300),
			},
		},
	}

	got, errs := ObserveAccessTokenInactivityTimeout(invalidLister{}, events.NewInMemoryRecorder("fakeRecorder"), existingConfig)

	// There must be only one kind of error asserting the lister type.
	if len(errs) != 1 {
		t.Errorf("expected 1 error. got %d errors", len(errs))
	}

	if !equality.Semantic.DeepEqual(got, existingConfig) {
		t.Errorf("result does not match expected config: %s", diff.ObjectDiff(existingConfig, got))
	}

}

// invalidLister is used for testing the case where a lister that does not implement OAuthLister is passed.
type invalidLister struct{}

func (l invalidLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (l invalidLister) PreRunHasSynced() []cache.InformerSynced {
	return nil
}
