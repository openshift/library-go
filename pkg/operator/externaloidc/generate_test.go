package externaloidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	configv1 "github.com/openshift/api/config/v1"
	authenticationv1alpha1 "github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/utils/ptr"
)

const configNamespace = "openshift-config"

var (
	testCertData = "fake-ca-cert"

	baseAuthResource = *newAuthWithSpec(configv1.AuthenticationSpec{
		Type: configv1.AuthenticationTypeOIDC,
		OIDCProviders: []configv1.OIDCProvider{
			{
				Name: "test-oidc-provider",
				Issuer: configv1.TokenIssuer{
					CertificateAuthority: configv1.ConfigMapNameReference{Name: "oidc-ca-bundle"},
					Audiences:            []configv1.TokenAudience{"my-test-aud", "another-aud"},
				},
				OIDCClients: []configv1.OIDCClientConfig{
					{
						ComponentName:      "console",
						ComponentNamespace: "openshift-console",
						ClientID:           "console-oidc-client",
					},
					{
						ComponentName:      "kube-apiserver",
						ComponentNamespace: "openshift-kube-apiserver",
						ClientID:           "test-oidc-client",
					},
				},
				ClaimMappings: configv1.TokenClaimMappings{
					Username: configv1.UsernameClaimMapping{
						Claim:        "username",
						PrefixPolicy: configv1.Prefix,
						Prefix: &configv1.UsernamePrefix{
							PrefixString: "oidc-user:",
						},
					},
					Groups: configv1.PrefixedClaimMapping{
						TokenClaimMapping: configv1.TokenClaimMapping{
							Claim: "groups",
						},
						Prefix: "oidc-group:",
					},
				},
				ClaimValidationRules: []configv1.TokenClaimValidationRule{
					{
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "username",
							RequiredValue: "test-username",
						},
					},
					{
						Type: configv1.TokenValidationRuleTypeRequiredClaim,
						RequiredClaim: &configv1.TokenRequiredClaim{
							Claim:         "email",
							RequiredValue: "test-email",
						},
					},
				},
			},
		},
	})

	baseAuthConfig = authenticationv1alpha1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       kindAuthenticationConfiguration,
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		JWT: []authenticationv1alpha1.JWTAuthenticator{
			{
				Issuer: &authenticationv1alpha1.Issuer{
					Audiences:            []string{"my-test-aud", "another-aud"},
					CertificateAuthority: testCertData,
					AudienceMatchPolicy:  authenticationv1alpha1.AudienceMatchPolicyMatchAny,
				},
				ClaimMappings: &authenticationv1alpha1.ClaimMappings{
					UID: authenticationv1alpha1.ClaimOrExpression{
						Claim: "sub",
					},
					Username: authenticationv1alpha1.PrefixedClaimOrExpression{
						Claim:  "username",
						Prefix: ptr.To("oidc-user:"),
					},
					Groups: authenticationv1alpha1.PrefixedClaimOrExpression{
						Claim:  "groups",
						Prefix: ptr.To("oidc-group:"),
					},
				},
				ClaimValidationRules: []authenticationv1alpha1.ClaimValidationRule{
					{
						Claim:         "username",
						RequiredValue: "test-username",
					},
					{
						Claim:         "email",
						RequiredValue: "test-email",
					},
				},
			},
		},
	}

	baseCABundleConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": testCertData,
		},
	}

	caBundleConfigMapInvalidKey = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"invalid": testCertData,
		},
	}

	caBundleConfigMapNoData = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-ca-bundle",
			Namespace: configNamespace,
		},
		Data: map[string]string{
			"ca-bundle.crt": "",
		},
	}
)

func TestAuthenticationConfigurationGeneratorGenerateAuthenticationConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string

		auth              configv1.Authentication
		caBundleConfigMap *corev1.ConfigMap
		configMapIndexer  cache.Indexer
		secretIndexer     cache.Indexer
		configValidator   validationFunc

		expectedAuthConfig          *authenticationv1alpha1.AuthenticationConfiguration
		expectError                 bool
		errorContains               string
		withExternalClaimsSourcing  bool
		withoutClientSecretResolver bool
	}{
		{
			name:             "ca bundle configmap lister error",
			auth:             baseAuthResource,
			configMapIndexer: cache.Indexer(&everFailingIndexer{}),
			expectError:      true,
		},
		{
			name:              "ca bundle configmap without required key",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapInvalidKey,
			expectError:       true,
		},
		{
			name:              "ca bundle configmap with no data",
			auth:              baseAuthResource,
			caBundleConfigMap: &caBundleConfigMapNoData,
			expectError:       true,
		},
		{
			name:              "auth config nil prefix when required",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.Prefix,
							Prefix:       nil,
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config invalid prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.UsernamePrefixPolicy("invalid-policy"),
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with nil claim in validation rule",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(copy *configv1.Authentication) {
					for i := range copy.Spec.OIDCProviders {
						if len(copy.Spec.OIDCProviders[i].ClaimValidationRules) == 0 {
							copy.Spec.OIDCProviders[i].ClaimValidationRules = make([]configv1.TokenClaimValidationRule, 0)
						}
						copy.Spec.OIDCProviders[i].ClaimValidationRules = append(
							copy.Spec.OIDCProviders[i].ClaimValidationRules,
							configv1.TokenClaimValidationRule{
								Type:          configv1.TokenValidationRuleTypeRequiredClaim,
								RequiredClaim: nil,
							},
						)
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "valid auth config",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = "https://example.com"
				},
			}),
			expectError: false,
		},
		{
			name:              "valid auth config during generation, validator fails",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
					}
				},
			}),
			expectError: true,

			configValidator: func(_ context.Context, _ *authenticationv1alpha1.AuthenticationConfiguration) error {
				return errors.New("boom")
			},
		},
		{
			name: "valid auth config with empty CA name",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.CertificateAuthority.Name = ""
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.CertificateAuthority = ""
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with default prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "email",
							PrefixPolicy: configv1.NoOpinion,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Claim:  "email",
							Prefix: ptr.To(""),
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with default prefix policy and username claim email",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.NoOpinion,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To("https://example.com#"),
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with no prefix policy",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.NoPrefix,
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To(""),
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with username claim prefix",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:        "username",
							PrefixPolicy: configv1.Prefix,
							Prefix: &configv1.UsernamePrefix{
								PrefixString: "oidc-user:",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Claim:  "username",
							Prefix: ptr.To("oidc-user:"),
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with empty string for username claim",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim: "",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with no uid claim or expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth:              baseAuthResource,
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = "sub"
					}
				},
			}),
			expectError:                false,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "auth config with uid claim and expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
							Claim:      "sub",
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with uid expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.UID = &configv1.TokenClaimOrExpressionMapping{
							Claim:      "",
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = ""
						authConfig.JWT[i].ClaimMappings.UID.Expression = "claims.sub"
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with extra missing key",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								ValueExpression: "claims.foo",
							},
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with extra missing valueExpression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key: "foo.example.com/bar",
							},
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with valid extra mappings",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key:             "foo.example.com/bar",
								ValueExpression: "claims.bar",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.UID.Claim = "sub"
						authConfig.JWT[i].ClaimMappings.Extra = []authenticationv1alpha1.ExtraMapping{
							{
								Key:             "foo.example.com/bar",
								ValueExpression: "claims.bar",
							},
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name: "invalid discovery URL (http instead of https)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "http://insecure-url.com"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap, // ensure CA bundle exists
			expectError:       true,
		},
		{
			name: "invalid discovery URL (identical to issuer URL)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = auth.Spec.OIDCProviders[0].Issuer.URL
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (identical to issuer URL except trailing slash)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://issuer.example.com/"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (missing host)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https:///path"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (contains user info)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://user@discovery.example.com/path"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (contains query string)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://discovery.example.com/path?q=1"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (contains fragment)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://discovery.example.com/path#fragment"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name: "invalid discovery URL (parse error)",
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].Issuer.URL = "https://issuer.example.com"
					auth.Spec.OIDCProviders[0].Issuer.DiscoveryURL = "https://%zz"
				},
			}),
			caBundleConfigMap: &baseCABundleConfigMap,
			expectError:       true,
		},
		{
			name:              "user validation rule invalid expression",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					auth.Spec.OIDCProviders[0].UserValidationRules = []configv1.TokenUserValidationRule{
						{
							Expression: "", // invalid: empty expression
							Message:    "must have a valid expression",
						},
					}
				},
			}),
			expectError:   true,
			errorContains: "userValidationRule expression must be non-empty",
		},
		{
			name:              "auth config with invalid username expression, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "#@!$&*(^)",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with invalid groups expression, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "#@!$&*(^)",
							},
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with username expression mapping",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.sub",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Expression: "claims.sub",
						}
						authConfig.JWT[i].ClaimMappings.UID = authenticationv1alpha1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with groups expression mapping",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "claims.groups",
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Groups = authenticationv1alpha1.PrefixedClaimOrExpression{
							Expression: "claims.groups",
						}
						authConfig.JWT[i].ClaimMappings.UID = authenticationv1alpha1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with username claim and expression both set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Claim:      "username",
							Expression: "claims.email",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with groups claim and expression both set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Claim:      "groups",
								Expression: "claims.groups",
							},
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with username expression and prefix set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression:   "claims.email",
							PrefixPolicy: configv1.Prefix,
							Prefix: &configv1.UsernamePrefix{
								PrefixString: "oidc-user:",
							},
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with groups expression and prefix set, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Groups = configv1.PrefixedClaimMapping{
							TokenClaimMapping: configv1.TokenClaimMapping{
								Expression: "claims.groups",
							},
							Prefix: "oidc-group:",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with username expression using claims.email without claims.email_verified, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
					}
				},
			}),
			expectError: true,
		},
		{
			name:              "auth config with username expression using claims.email with claims.email_verified in claimValidationRule, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
						auth.Spec.OIDCProviders[i].ClaimValidationRules = []configv1.TokenClaimValidationRule{
							{
								Type: configv1.TokenValidationRuleTypeCEL,
								CEL: configv1.TokenClaimValidationCELRule{
									Expression: "claims.email_verified == true",
									Message:    "email must be verified",
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Expression: "claims.email",
						}
						authConfig.JWT[i].ClaimMappings.UID = authenticationv1alpha1.ClaimOrExpression{
							Claim: "sub",
						}
						authConfig.JWT[i].ClaimValidationRules = []authenticationv1alpha1.ClaimValidationRule{
							{
								Expression: "claims.email_verified == true",
								Message:    "email must be verified",
							},
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with username expression using both claims.email and claims.email_verified, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email_verified ? claims.email : 'unverified'",
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Expression: "claims.email_verified ? claims.email : 'unverified'",
						}
						authConfig.JWT[i].ClaimMappings.UID = authenticationv1alpha1.ClaimOrExpression{
							Claim: "sub",
						}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "auth config with username expression using claims.email with claims.email_verified in extra, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].ClaimMappings.Username = configv1.UsernameClaimMapping{
							Expression: "claims.email",
						}
						auth.Spec.OIDCProviders[i].ClaimMappings.Extra = []configv1.ExtraMapping{
							{
								Key:             "example.com/email-verified",
								ValueExpression: "claims.email_verified ? 'true' : 'false'",
							},
						}
						auth.Spec.OIDCProviders[i].ClaimValidationRules = []configv1.TokenClaimValidationRule{}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].ClaimMappings.Username = authenticationv1alpha1.PrefixedClaimOrExpression{
							Expression: "claims.email",
						}
						authConfig.JWT[i].ClaimMappings.UID = authenticationv1alpha1.ClaimOrExpression{
							Claim: "sub",
						}
						authConfig.JWT[i].ClaimMappings.Extra = []authenticationv1alpha1.ExtraMapping{
							{
								Key:             "example.com/email-verified",
								ValueExpression: "claims.email_verified ? 'true' : 'false'",
							},
						}
						authConfig.JWT[i].ClaimValidationRules = []authenticationv1alpha1.ClaimValidationRule{}
					}
				},
			}),
			expectError: false,
		},
		{
			name:              "valid auth config with external claims source using request provided token auth and conditions, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			configMapIndexer: func() cache.Indexer {
				idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				mustAddToIndexer(t, idx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ext-source-ca-bundle",
						Namespace: configNamespace,
					},
					Data: map[string]string{
						"ca-bundle.crt": testCertData,
					},
				})
				return idx
			}(),
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
								},
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "ext-source-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
								Predicates: []configv1.ExternalSourcePredicate{
									{
										Expression: "has(claims.sub)",
									},
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ExternalClaimsSources = []authenticationv1alpha1.ExternalClaimsSource{
							{
								Authentication: &authenticationv1alpha1.Authentication{
									Type: ptr.To(authenticationv1alpha1.AuthenticationTypeRequestProvidedToken),
								},
								TLS: &authenticationv1alpha1.TLS{
									CertificateAuthority: ptr.To(testCertData),
								},
								URL: &authenticationv1alpha1.SourceURL{
									Hostname:       ptr.To("claims.example.com"),
									PathExpression: ptr.To("claims.sub"),
								},
								Mappings: []authenticationv1alpha1.SourcedClaimMapping{
									{
										Name:       ptr.To("custom_claim"),
										Expression: ptr.To("response.custom_claim"),
									},
								},
								Conditions: []authenticationv1alpha1.ExternalSourceCondition{
									{
										Expression: ptr.To("has(claims.sub)"),
									},
								},
							},
						}
					}
				},
			}),
			expectError:                 false,
			withExternalClaimsSourcing:  true,
			withoutClientSecretResolver: true,
		},
		{
			name:              "valid auth config with external claims source using request provided token auth and conditions, no ca bundle specified, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
								},
								TLS: configv1.ExternalSourceTLS{},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
								Predicates: []configv1.ExternalSourcePredicate{
									{
										Expression: "has(claims.sub)",
									},
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ExternalClaimsSources = []authenticationv1alpha1.ExternalClaimsSource{
							{
								Authentication: &authenticationv1alpha1.Authentication{
									Type: ptr.To(authenticationv1alpha1.AuthenticationTypeRequestProvidedToken),
								},
								TLS: nil,
								URL: &authenticationv1alpha1.SourceURL{
									Hostname:       ptr.To("claims.example.com"),
									PathExpression: ptr.To("claims.sub"),
								},
								Mappings: []authenticationv1alpha1.SourcedClaimMapping{
									{
										Name:       ptr.To("custom_claim"),
										Expression: ptr.To("response.custom_claim"),
									},
								},
								Conditions: []authenticationv1alpha1.ExternalSourceCondition{
									{
										Expression: ptr.To("has(claims.sub)"),
									},
								},
							},
						}
					}
				},
			}),
			expectError:                false,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "valid auth config with external claims source using anonymous auth, success",
			caBundleConfigMap: &baseCABundleConfigMap,
			configMapIndexer: func() cache.Indexer {
				idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				mustAddToIndexer(t, idx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ext-source-ca-bundle",
						Namespace: configNamespace,
					},
					Data: map[string]string{
						"ca-bundle.crt": testCertData,
					},
				})
				return idx
			}(),
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "ext-source-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ExternalClaimsSources = []authenticationv1alpha1.ExternalClaimsSource{
							{
								TLS: &authenticationv1alpha1.TLS{
									CertificateAuthority: ptr.To(testCertData),
								},
								URL: &authenticationv1alpha1.SourceURL{
									Hostname:       ptr.To("claims.example.com"),
									PathExpression: ptr.To("claims.sub"),
								},
								Mappings: []authenticationv1alpha1.SourcedClaimMapping{
									{
										Name:       ptr.To("custom_claim"),
										Expression: ptr.To("response.custom_claim"),
									},
								},
							},
						}
					}
				},
			}),
			expectError:                false,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "valid auth config with external claims source using client credential auth",
			caBundleConfigMap: &baseCABundleConfigMap,
			configMapIndexer: func() cache.Indexer {
				idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				mustAddToIndexer(t, idx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ext-source-ca-bundle",
						Namespace: configNamespace,
					},
					Data: map[string]string{
						"ca-bundle.crt": testCertData,
					},
				})
				mustAddToIndexer(t, idx, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "cc-tls-ca-bundle",
						Namespace: configNamespace,
					},
					Data: map[string]string{
						"ca-bundle.crt": testCertData,
					},
				})
				return idx
			}(),
			secretIndexer: func() cache.Indexer {
				idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				mustAddToIndexer(t, idx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client-secret-ref",
						Namespace: configNamespace,
					},
					Data: map[string][]byte{
						"client-secret": []byte("my-secret-value"),
					},
				})
				return idx
			}(),
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeClientCredential,
									ClientCredential: configv1.ClientCredentialConfig{
										ClientID: "my-client-id",
										ClientSecret: configv1.ClientSecretSecretReference{
											Name: "client-secret-ref",
										},
										TokenEndpoint: "https://idp.example.com/oauth2/token",
										Scopes:        []configv1.OAuth2Scope{"openid", "profile"},
										TLS: configv1.ExternalSourceTLS{
											CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
												Name: "cc-tls-ca-bundle",
											},
										},
									},
								},
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "ext-source-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
						authConfig.JWT[i].ExternalClaimsSources = []authenticationv1alpha1.ExternalClaimsSource{
							{
								Authentication: &authenticationv1alpha1.Authentication{
									Type: ptr.To(authenticationv1alpha1.AuthenticationTypeClientCredential),
									ClientCredential: &authenticationv1alpha1.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-secret-value",
										TokenEndpoint: "https://idp.example.com/oauth2/token",
										Scopes:        []string{"openid", "profile"},
										TLS: &authenticationv1alpha1.TLS{
											CertificateAuthority: ptr.To(testCertData),
										},
									},
								},
								TLS: &authenticationv1alpha1.TLS{
									CertificateAuthority: ptr.To(testCertData),
								},
								URL: &authenticationv1alpha1.SourceURL{
									Hostname:       ptr.To("claims.example.com"),
									PathExpression: ptr.To("claims.sub"),
								},
								Mappings: []authenticationv1alpha1.SourcedClaimMapping{
									{
										Name:       ptr.To("custom_claim"),
										Expression: ptr.To("response.custom_claim"),
									},
								},
							},
						}
					}
				},
			}),
			expectError:                false,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "client credential external claims source without a client secret resolver, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeClientCredential,
									ClientCredential: configv1.ClientCredentialConfig{
										ClientSecret: configv1.ClientSecretSecretReference{Name: "client-secret-ref"},
									},
								},
							},
						}
					}
				},
			}),
			expectError:                 true,
			errorContains:               "client secret resolver is required",
			withExternalClaimsSourcing:  true,
			withoutClientSecretResolver: true,
		},
		{
			name:              "auth config with external claims source with unknown auth type, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationType("UnknownType"),
								},
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "ext-source-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
							},
						}
					}
				},
			}),
			expectError:                true,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "auth config with external claims source with missing TLS CA configmap, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
								},
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "nonexistent-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
							},
						}
					}
				},
			}),
			expectError:                true,
			withExternalClaimsSourcing: true,
		},
		{
			name:              "auth config with external claims source with client secret key missing in secret, error",
			caBundleConfigMap: &baseCABundleConfigMap,
			secretIndexer: func() cache.Indexer {
				idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
				mustAddToIndexer(t, idx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client-secret-ref",
						Namespace: configNamespace,
					},
					Data: map[string][]byte{
						"wrong-key": []byte("my-secret-value"),
					},
				})
				return idx
			}(),
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeClientCredential,
									ClientCredential: configv1.ClientCredentialConfig{
										ClientID: "my-client-id",
										ClientSecret: configv1.ClientSecretSecretReference{
											Name: "client-secret-ref",
										},
										TokenEndpoint: "https://idp.example.com/oauth2/token",
									},
								},
								TLS: configv1.ExternalSourceTLS{
									CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
										Name: "ext-source-ca-bundle",
									},
								},
								URL: configv1.SourceURL{
									Hostname:       "claims.example.com",
									PathExpression: "claims.sub",
								},
								Mappings: []configv1.SourcedClaimMapping{
									{
										Name:       "custom_claim",
										Expression: "response.custom_claim",
									},
								},
							},
						}
					}
				},
			}),
			expectError:                true,
			withExternalClaimsSourcing: true,
		},

		{
			name:              "auth config with external claims source configured but feature gate disabled",
			caBundleConfigMap: &baseCABundleConfigMap,
			auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
				func(auth *configv1.Authentication) {
					for i := range auth.Spec.OIDCProviders {
						auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
						auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
							{
								Authentication: configv1.ExternalSourceAuthentication{
									Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
								},
							},
						}
					}
				},
			}),
			expectedAuthConfig: authConfigWithUpdates(baseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					for i := range authConfig.JWT {
						authConfig.JWT[i].Issuer.URL = "https://example.com"
					}
				},
			}),
			expectError: false,
		},
		// TODO: Add tests for validating currently unvalidated fields due to dependency issues (CEL expression validation)
		// The following jira tickets track the work necessary to eventually enable this validation:
		// 1. https://redhat.atlassian.net/browse/CNTRLPLANE-3491
		// 2. https://redhat.atlassian.net/browse/CNTRLPLANE-3492
		// 3. https://redhat.atlassian.net/browse/CNTRLPLANE-3493
		/*
			{
				name:              "auth config with duplicate mapping names across external claims sources",
				caBundleConfigMap: &baseCABundleConfigMap,
				configMapIndexer: func() cache.Indexer {
					idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
					idx.Add(&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "ext-source-ca-bundle",
							Namespace: configNamespace,
						},
						Data: map[string]string{
							"ca-bundle.crt": testCertData,
						},
					})
					return idx
				}(),
				auth: *authWithUpdates(baseAuthResource, []func(auth *configv1.Authentication){
					func(auth *configv1.Authentication) {
						for i := range auth.Spec.OIDCProviders {
							auth.Spec.OIDCProviders[i].Issuer.URL = "https://example.com"
							auth.Spec.OIDCProviders[i].ExternalClaimsSources = []configv1.ExternalClaimsSource{
								{
									Authentication: configv1.ExternalSourceAuthentication{
										Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
									},
									TLS: configv1.ExternalSourceTLS{
										CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
											Name: "ext-source-ca-bundle",
										},
									},
									URL: configv1.SourceURL{
										Hostname:       "source-one.example.com",
										PathExpression: "claims.sub",
									},
									Mappings: []configv1.SourcedClaimMapping{
										{
											Name:       "custom_claim",
											Expression: "response.custom_claim",
										},
									},
								},
								{
									Authentication: configv1.ExternalSourceAuthentication{
										Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
									},
									TLS: configv1.ExternalSourceTLS{
										CertificateAuthority: configv1.ExternalSourceCertificateAuthorityConfigMapReference{
											Name: "ext-source-ca-bundle",
										},
									},
									URL: configv1.SourceURL{
										Hostname:       "source-two.example.com",
										PathExpression: "claims.sub",
									},
									Mappings: []configv1.SourcedClaimMapping{
										{
											Name:       "custom_claim",
											Expression: "response.other_claim",
										},
									},
								},
							}
						}
					},
				}),
				expectError: true,
			withExternalClaimsSourcing: true,
			},
		*/
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configMapIndexer == nil {
				tt.configMapIndexer = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			}

			if tt.caBundleConfigMap != nil {
				mustAddToIndexer(t, tt.configMapIndexer, tt.caBundleConfigMap)
			}

			options := GeneratorOptions{
				CertificateAuthorityResolver: newTestCABundleResolver(corev1listers.NewConfigMapLister(tt.configMapIndexer)),
			}
			if tt.withExternalClaimsSourcing {
				options.ExternalClaimsSourcing = &ExternalClaimsSourcingOptions{}
				if !tt.withoutClientSecretResolver {
					options.ExternalClaimsSourcing.ClientSecretResolver = newTestClientSecretResolver(corev1listers.NewSecretLister(tt.secretIndexer))
				}
			}
			c := NewAuthenticationConfigurationGenerator(options)
			c.validationFn = tt.configValidator

			gotConfig, err := c.GenerateAuthenticationConfiguration(context.Background(), &tt.auth.Spec)
			if tt.expectError && err == nil {
				t.Fatalf("expected error but didn't get any")
			}

			if !tt.expectError && err != nil {
				t.Fatalf("did not expect any error but got: %v", err)
			}
			if tt.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errorContains)) {
				t.Fatalf("expected error containing %q, got %v", tt.errorContains, err)
			}

			if gotConfig == nil && tt.expectedAuthConfig == nil {
				return
			}

			if diff := cmp.Diff(tt.expectedAuthConfig, gotConfig, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("unexpected config diff: %s", diff)
			}
		})
	}
}

func TestAuthenticationConfigurationGeneratorRejectsInvalidInputs(t *testing.T) {
	t.Run("nil authentication spec", func(t *testing.T) {
		generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{})

		config, err := generator.GenerateAuthenticationConfiguration(context.Background(), nil)
		if err == nil || err.Error() != "authentication spec cannot be nil" {
			t.Fatalf("expected nil authentication spec error, got %v", err)
		}
		if config != nil {
			t.Fatalf("expected no configuration, got %#v", config)
		}
	})

	t.Run("missing certificate authority resolver", func(t *testing.T) {
		generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{})

		_, err := generator.getCertificateAuthority("issuer-ca")
		if err == nil || err.Error() != "certificate authority resolver is required" {
			t.Fatalf("expected missing certificate authority resolver error, got %v", err)
		}
	})

	t.Run("missing client secret resolver", func(t *testing.T) {
		generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{
			ExternalClaimsSourcing: &ExternalClaimsSourcingOptions{},
		})

		_, err := generator.getClientSecret("client-secret")
		if err == nil || err.Error() != "client secret resolver is required" {
			t.Fatalf("expected missing client secret resolver error, got %v", err)
		}
	})

	t.Run("resolver errors retain their cause and resource name", func(t *testing.T) {
		resolverErr := errors.New("resource not found")
		generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{
			CertificateAuthorityResolver: func(string) (string, error) { return "", resolverErr },
			ExternalClaimsSourcing: &ExternalClaimsSourcingOptions{
				ClientSecretResolver: func(string) (string, error) { return "", resolverErr },
			},
		})

		_, err := generator.getCertificateAuthority("issuer-ca")
		if !errors.Is(err, resolverErr) || !strings.Contains(err.Error(), `certificate authority ConfigMap "issuer-ca"`) {
			t.Fatalf("expected CA resolver error to identify issuer-ca and retain its cause, got %v", err)
		}

		_, err = generator.getClientSecret("client-secret")
		if !errors.Is(err, resolverErr) || !strings.Contains(err.Error(), `client Secret "client-secret"`) {
			t.Fatalf("expected client Secret resolver error to identify client-secret and retain its cause, got %v", err)
		}
	})
}

func TestGenerateExternalClaimsSourceAuthenticationClientCredentialWithoutTLS(t *testing.T) {
	generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{
		ExternalClaimsSourcing: &ExternalClaimsSourcingOptions{
			ClientSecretResolver: func(name string) (string, error) {
				return "client-secret", nil
			},
		},
	})

	clientCredential, err := generator.generateExternalClaimsSourceAuthenticationClientCredential(configv1.ClientCredentialConfig{
		ClientID: "client-id",
		ClientSecret: configv1.ClientSecretSecretReference{
			Name: "client-secret",
		},
		TokenEndpoint: "https://idp.example.com/token",
	})
	if err != nil {
		t.Fatalf("did not expect an error: %v", err)
	}
	if clientCredential.TLS != nil {
		t.Fatalf("expected TLS to be nil when no certificate authority is configured, got %#v", clientCredential.TLS)
	}
}

func TestGenerateExternalClaimsSourcesWithoutClientSecretResolver(t *testing.T) {
	generator := NewAuthenticationConfigurationGenerator(GeneratorOptions{
		ExternalClaimsSourcing: &ExternalClaimsSourcingOptions{},
	})

	sources, err := generator.generateExternalClaimsSources(configv1.ExternalClaimsSource{
		Authentication: configv1.ExternalSourceAuthentication{
			Type: configv1.ExternalSourceAuthenticationTypeRequestProvidedToken,
		},
	})
	if err != nil {
		t.Fatalf("did not expect an error without a client secret resolver: %v", err)
	}
	if len(sources) != 1 || sources[0].Authentication == nil {
		t.Fatalf("expected one request-token-authenticated source, got %#v", sources)
	}
}

func mustAddToIndexer(t testing.TB, indexer cache.Indexer, obj interface{}) {
	t.Helper()
	if err := indexer.Add(obj); err != nil {
		t.Fatalf("adding %T to indexer: %v", obj, err)
	}
}

func newAuthWithSpec(spec configv1.AuthenticationSpec) *configv1.Authentication {
	return &configv1.Authentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: spec,
	}
}

func authWithUpdates(auth configv1.Authentication, updateFuncs []func(auth *configv1.Authentication)) *configv1.Authentication {
	copy := auth.DeepCopy()
	for _, updateFunc := range updateFuncs {
		updateFunc(copy)
	}
	return copy
}

func authConfigWithUpdates(authConfig authenticationv1alpha1.AuthenticationConfiguration, updateFuncs []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration)) *authenticationv1alpha1.AuthenticationConfiguration {
	copy := authConfig.DeepCopy()
	for _, updateFunc := range updateFuncs {
		updateFunc(copy)
	}
	return copy
}

type everFailingIndexer struct{}

// Index always returns an error
func (i *everFailingIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return nil, fmt.Errorf("Index method not implemented")
}

// IndexKeys always returns an error
func (i *everFailingIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, fmt.Errorf("IndexKeys method not implemented")
}

// ListIndexFuncValues always returns an error
func (i *everFailingIndexer) ListIndexFuncValues(indexName string) []string {
	return nil
}

// ByIndex always returns an error
func (i *everFailingIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	return nil, fmt.Errorf("ByIndex method not implemented")
}

// GetIndexers always returns an error
func (i *everFailingIndexer) GetIndexers() cache.Indexers {
	return nil
}

// AddIndexers always returns an error
func (i *everFailingIndexer) AddIndexers(newIndexers cache.Indexers) error {
	return fmt.Errorf("AddIndexers method not implemented")
}

// Add always returns an error
func (s *everFailingIndexer) Add(obj interface{}) error {
	return fmt.Errorf("Add method not implemented")
}

// Update always returns an error
func (s *everFailingIndexer) Update(obj interface{}) error {
	return fmt.Errorf("Update method not implemented")
}

// Delete always returns an error
func (s *everFailingIndexer) Delete(obj interface{}) error {
	return fmt.Errorf("Delete method not implemented")
}

// List always returns nil
func (s *everFailingIndexer) List() []interface{} {
	return nil
}

// ListKeys always returns nil
func (s *everFailingIndexer) ListKeys() []string {
	return nil
}

// LastStoreSyncResourceVersion always returns an empty resource version.
func (s *everFailingIndexer) LastStoreSyncResourceVersion() string {
	return ""
}

// Bookmark intentionally ignores resource-version updates.
func (s *everFailingIndexer) Bookmark(rv string) {}

// Get always returns an error
func (s *everFailingIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("Get method not implemented")
}

// GetByKey always returns an error
func (s *everFailingIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, fmt.Errorf("GetByKey method not implemented")
}

// Replace always returns an error
func (s *everFailingIndexer) Replace(objects []interface{}, sKey string) error {
	return fmt.Errorf("Replace method not implemented")
}

// Resync always returns an error
func (s *everFailingIndexer) Resync() error {
	return fmt.Errorf("Resync method not implemented")
}

var (
	baseCACert, baseCAPrivateKey, validateTestCertData = func() (*x509.Certificate, crypto.Signer, string) {
		cert, key, err := generateCAKeyPair()
		if err != nil {
			panic(err)
		}
		return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}()

	validateBaseAuthConfig = authenticationv1alpha1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       kindAuthenticationConfiguration,
			APIVersion: authenticationv1alpha1.SchemeGroupVersion.String(),
		},
		JWT: []authenticationv1alpha1.JWTAuthenticator{
			{
				Issuer: &authenticationv1alpha1.Issuer{
					Audiences:            []string{"my-test-aud", "another-aud"},
					CertificateAuthority: validateTestCertData,
					AudienceMatchPolicy:  authenticationv1alpha1.AudienceMatchPolicyMatchAny,
				},
				ClaimMappings: &authenticationv1alpha1.ClaimMappings{
					Username: authenticationv1alpha1.PrefixedClaimOrExpression{
						Claim:  "username",
						Prefix: ptr.To("oidc-user:"),
					},
					Groups: authenticationv1alpha1.PrefixedClaimOrExpression{
						Claim:  "groups",
						Prefix: ptr.To("oidc-group:"),
					},
				},
				ClaimValidationRules: []authenticationv1alpha1.ClaimValidationRule{
					{
						Claim:         "username",
						RequiredValue: "test-username",
					},
					{
						Claim:         "email",
						RequiredValue: "test-email",
					},
				},
			},
		},
	}
)

func TestValidateOAuthApiserverAuthenticationConfiguration(t *testing.T) {
	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, nil)
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	untrustedCACert, _, err := generateCAKeyPair()
	if err != nil {
		t.Fatalf("could not create untrusted CA: %v", err)
	}
	untrustedCACertData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedCACert.Raw}))

	for _, tt := range []struct {
		name          string
		authConfig    *authenticationv1alpha1.AuthenticationConfiguration
		expectError   bool
		errorContains string
	}{
		{
			name:        "empty config",
			authConfig:  &authenticationv1alpha1.AuthenticationConfiguration{},
			expectError: false,
		},
		{
			name:        "nil config",
			authConfig:  nil,
			expectError: false,
		},
		{
			name: "issuer with empty URL",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = ""
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with untrusted CA",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = testServer.URL
					authConfig.JWT[0].Issuer.CertificateAuthority = untrustedCACertData
				},
			}),
			expectError:   true,
			errorContains: testServer.URL,
		},
		{
			name: "issuer with HTTP URL returns a non-OK response",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = strings.Replace(testServer.URL, "https://", "http://", 1)
				},
			}),
			expectError: true,
		},
		{
			name: "issuer with invalid CA",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.CertificateAuthority = "invalid CA"
				},
			}),
			expectError: true,
		},
		{
			name: "valid auth config",
			authConfig: authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
				func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
					authConfig.JWT[0].Issuer.URL = testServer.URL
				},
			}),
			expectError: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOAuthApiserverAuthenticationConfiguration(context.Background(), tt.authConfig)
			if tt.expectError && err == nil {
				t.Errorf("expected error but didn't get any")
			}
			if tt.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errorContains)) {
				t.Errorf("expected error containing %q, got %v", tt.errorContains, err)
			}

			if !tt.expectError && err != nil {
				t.Errorf("did not expect any error but got: %v", err)
			}
		})
	}
}

func TestValidateOAuthApiserverAuthenticationConfigurationLimitsErrorResponseBody(t *testing.T) {
	const responseBodySize = 2048
	testServer, err := createTestServer(baseCACert, baseCAPrivateKey, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, strings.Repeat("x", responseBodySize))
	})
	if err != nil {
		t.Fatalf("could not create test server: %v", err)
	}
	defer testServer.Close()
	testServer.StartTLS()

	authConfig := authConfigWithUpdates(validateBaseAuthConfig, []func(authConfig *authenticationv1alpha1.AuthenticationConfiguration){
		func(authConfig *authenticationv1alpha1.AuthenticationConfiguration) {
			authConfig.JWT[0].Issuer.URL = testServer.URL
		},
	})

	err = validateOAuthApiserverAuthenticationConfiguration(context.Background(), authConfig)
	if err == nil {
		t.Fatal("expected an error for a non-OK response")
	}
	if !strings.Contains(err.Error(), strings.Repeat("x", 1024)) {
		t.Fatal("expected error to include the first 1024 response bytes")
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 1025)) {
		t.Fatal("expected error response body to be limited to 1024 bytes")
	}
}

func createTestServer(caCert *x509.Certificate, caPrivateKey crypto.Signer, handlerFunc http.HandlerFunc) (*httptest.Server, error) {
	cert := caCert
	key := caPrivateKey
	var err error
	if caCert == nil {
		cert, key, err = generateCAKeyPair()
		if err != nil {
			return nil, err
		}
	}

	servingCertPair, err := generateServingCert(cert, key)
	if err != nil {
		return nil, err
	}

	if handlerFunc == nil {
		handlerFunc = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	testServer := httptest.NewUnstartedServer(handlerFunc)
	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*servingCertPair},
	}

	return testServer, nil
}

func generateCAKeyPair() (*x509.Certificate, crypto.Signer, error) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivateKey, err
}

func generateServingCert(caCert *x509.Certificate, caPrivateKey crypto.Signer) (*tls.Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Springfield"},
			StreetAddress: []string{"742 Evergreen Terrace"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("PEM encoding certificate: %w", err)
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, fmt.Errorf("PEM encoding private key: %w", err)
	}

	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &serverCert, nil
}

func newTestCABundleResolver(cmLister corev1listers.ConfigMapLister) CertificateAuthorityResolver {
	return func(name string) (string, error) {
		cm, err := cmLister.ConfigMaps(configNamespace).Get(name)
		if err != nil {
			return "", fmt.Errorf("could not retrieve configmap %s/%s: %v", configNamespace, name, err)
		}
		caData, ok := cm.Data["ca-bundle.crt"]
		if !ok || len(caData) == 0 {
			return "", fmt.Errorf("configmap %s/%s key \"ca-bundle.crt\" missing or empty", configNamespace, name)
		}
		return caData, nil
	}
}

func newTestClientSecretResolver(secretLister corev1listers.SecretLister) ClientSecretResolver {
	return func(name string) (string, error) {
		secret, err := secretLister.Secrets(configNamespace).Get(name)
		if err != nil {
			return "", fmt.Errorf("could not retrieve secret %s/%s: %v", configNamespace, name, err)
		}
		clientSecret, ok := secret.Data["client-secret"]
		if !ok || len(clientSecret) == 0 {
			return "", fmt.Errorf("secret %s/%s key \"client-secret\" missing or empty", configNamespace, name)
		}
		return string(clientSecret), nil
	}
}
