package tlssecurityprofile

import (
	"context"
	"reflect"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/apiserver/jsonpatch"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	cipherSuitesPath = "cipher-suites"
	minVersionPath   = "minimum-tls-version"
	profileTypePath  = "profile-type"
)

func TestObserveTLSSecurityProfile(t *testing.T) {
	tests := []struct {
		name            string
		managementState operatorv1.ManagementState
		config          *configv1.TLSSecurityProfile
		expectedConfig  map[string]interface{}
	}{
		{
			name:            "NoAPIServerConfig",
			managementState: operatorv1.Managed,
			config:          nil,
			expectedConfig: map[string]interface{}{
				minVersionPath:  string(configv1.VersionTLS12),
				profileTypePath: "",
				cipherSuitesPath: []interface{}{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
				},
			},
		},
		{
			name:            "ModernCrypto",
			managementState: operatorv1.Managed,
			config: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileModernType,
				Modern: &configv1.ModernTLSProfile{},
			},
			expectedConfig: map[string]interface{}{
				minVersionPath:  string(configv1.VersionTLS13),
				profileTypePath: string(configv1.TLSProfileModernType),
				cipherSuitesPath: []interface{}{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
				},
			},
		},
		{
			name:            "IntermediateConfig",
			managementState: operatorv1.Managed,
			config: &configv1.TLSSecurityProfile{
				Type:         configv1.TLSProfileIntermediateType,
				Intermediate: &configv1.IntermediateTLSProfile{},
			},
			expectedConfig: map[string]interface{}{
				minVersionPath:  string(configv1.VersionTLS12),
				profileTypePath: string(configv1.TLSProfileIntermediateType),
				cipherSuitesPath: []interface{}{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
				},
			},
		},
		{
			name:            "OldCrypto",
			managementState: operatorv1.Managed,
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedConfig: map[string]interface{}{
				minVersionPath:  string(configv1.VersionTLS10),
				profileTypePath: string(configv1.TLSProfileOldType),
				cipherSuitesPath: []interface{}{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
					"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
					"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
					"TLS_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_RSA_WITH_AES_128_CBC_SHA256",
					"TLS_RSA_WITH_AES_128_CBC_SHA",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
					"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
				},
			},
		},
		{
			name:            "CustomCrypto",
			managementState: operatorv1.Managed,
			config: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
							"TLS_AES_256_GCM_SHA384",
							"TLS_CHACHA20_POLY1305_SHA256",
							// Inputs expect OpenSSL names and are mapped to IANA names that golang uses
							// via github.com/openshift/library-go/pkg/crypto.OpenSSLToIANACipherSuites()
							"ECDHE-ECDSA-AES128-GCM-SHA256",
							"ECDHE-RSA-AES128-GCM-SHA256",
						},
						MinTLSVersion: configv1.VersionTLS11,
					},
				},
			},
			expectedConfig: map[string]interface{}{
				minVersionPath:  string(configv1.VersionTLS11),
				profileTypePath: string(configv1.TLSProfileCustomType),
				cipherSuitesPath: []interface{}{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if tt.config != nil {
				if err := indexer.Add(&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Spec: configv1.APIServerSpec{
						TLSSecurityProfile: tt.config,
					},
				}); err != nil {
					t.Fatal(err)
				}
			}

			var result map[string]interface{}
			// Enough to make sync() happy
			controller := &tlsSecurityProfileController{
				controllerInstanceName: t.Name(),
				operatorClient:         mockOperatorClient{managementState: tt.managementState},
				apiserverConfigLister:  configlistersv1.NewAPIServerLister(indexer),
				callBack: func(config map[string]interface{}) {
					result = config
				},
				eventRecorder:      events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now())),
				lastObservedConfig: make(map[string]interface{}, 0),
				minTLSVersionPath:  []string{minVersionPath},
				cipherSuitesPath:   []string{cipherSuitesPath},
				profileTypePath:    []string{profileTypePath},
			}

			if err := controller.sync(context.Background(), mockSyncContext{}); err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(result, tt.expectedConfig) {
				t.Errorf("\ngot      = %v,\nexpected = %v", result, tt.expectedConfig)
			}
		})
	}
}

type mockSyncContext struct {
}

func (mockSyncContext) Queue() workqueue.RateLimitingInterface {
	panic("mockSyncContext.Queue() called")
}

func (mockSyncContext) QueueKey() string {
	panic("mockSyncContext.QueueKey() called")
}

func (mockSyncContext) Recorder() events.Recorder {
	panic("mockSyncContext.Recorder() called")
}

type mockOperatorClient struct {
	managementState operatorv1.ManagementState
}

func (m mockOperatorClient) GetOperatorState() (spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, resourceVersion string, err error) {
	return &operatorv1.OperatorSpec{
		ManagementState: m.managementState,
	}, nil, "", nil
}

func (mockOperatorClient) Informer() cache.SharedIndexInformer {
	panic("mockOperatorClient.Informer() called")
}

func (mockOperatorClient) GetObjectMeta() (meta *metav1.ObjectMeta, err error) {
	panic("mockOperatorClient.GetObjectMeta() called")
}

func (mockOperatorClient) GetOperatorStateWithQuorum(ctx context.Context) (spec *operatorv1.OperatorSpec, status *operatorv1.OperatorStatus, resourceVersion string, err error) {
	panic("mockOperatorClient.GetOperatorStateWithQuorum() called")
}

func (mockOperatorClient) UpdateOperatorSpec(ctx context.Context, oldResourceVersion string, in *operatorv1.OperatorSpec) (out *operatorv1.OperatorSpec, newResourceVersion string, err error) {
	panic("mockOperatorClient.UpdateOperatorSpec() called")
}

func (mockOperatorClient) UpdateOperatorStatus(ctx context.Context, oldResourceVersion string, in *operatorv1.OperatorStatus) (out *operatorv1.OperatorStatus, err error) {
	panic("mockOperatorClient.UpdateOperatorStatus() called")
}

func (mockOperatorClient) ApplyOperatorSpec(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorSpecApplyConfiguration) (err error) {
	panic("mockOperatorClient.ApplyOperatorSpec() called")
}
func (mockOperatorClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) (err error) {
	return nil
}

func (mockOperatorClient) PatchOperatorStatus(ctx context.Context, jsonPatch *jsonpatch.PatchSet) (err error) {
	panic("mockOperatorClient.PatcheOperatorStatus() called")
}
