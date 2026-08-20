package controllers

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
)

func createEncryptionCfgSecret(t *testing.T, targetNs string, revision string, encryptionCfg *encryptiondata.Config) *corev1.Secret {
	t.Helper()

	s, err := encryptiondata.ToSecret(targetNs, fmt.Sprintf("%s-%s", "encryption-config", revision), encryptionCfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var alwaysFulfilledPreconditions = func() (bool, error) { return true, nil }

type testProvider struct {
	encryptedGRs []schema.GroupResource
}

func newTestProvider(encryptedGRs []schema.GroupResource) Provider {
	return &testProvider{encryptedGRs: encryptedGRs}
}

func (p *testProvider) EncryptedGRs() []schema.GroupResource {
	return p.encryptedGRs
}

func (p *testProvider) ShouldRunEncryptionControllers() (bool, error) {
	return true, nil
}

// fakeEncryptionDeployer is a minimal statemachine.Deployer for unit tests that need to control the deployed encryption config and revision convergence.
type fakeEncryptionDeployer struct {
	secret    *corev1.Secret
	converged bool
	err       error
}

func (f *fakeEncryptionDeployer) DeployedEncryptionConfigSecret(_ context.Context) (*corev1.Secret, bool, error) {
	return f.secret, f.converged, f.err
}

func (f *fakeEncryptionDeployer) AddEventHandler(_ cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (f *fakeEncryptionDeployer) HasSynced() bool { return true }

var _ statemachine.Deployer = &fakeEncryptionDeployer{}
