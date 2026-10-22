package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	encryptiondatatesting "github.com/openshift/library-go/pkg/operator/encryption/encryptiondata/testing"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// statusValidatingOperatorClient mirrors the production ApplyOperatorStatus guard in
// genericoperatorclient: missing condition Type/Status panics instead of silently applying.
type statusValidatingOperatorClient struct {
	v1helpers.OperatorClient
}

func (c *statusValidatingOperatorClient) ApplyOperatorStatus(ctx context.Context, fieldManager string, applyConfiguration *applyoperatorv1.OperatorStatusApplyConfiguration) error {
	if applyConfiguration != nil {
		for i, curr := range applyConfiguration.Conditions {
			if len(ptr.Deref(curr.Type, "")) == 0 {
				panic(fmt.Sprintf(".status.conditions[%d].type is missing", i))
			}
			if len(ptr.Deref(curr.Status, "")) == 0 {
				panic(fmt.Sprintf(".status.conditions[%q].status is missing", *curr.Type))
			}
		}
	}
	return c.OperatorClient.ApplyOperatorStatus(ctx, fieldManager, applyConfiguration)
}

type fakeKMSHealthStatusProvider struct {
	status  *operatorv1.KMSEncryptionStatus
	getErr  error
	gets    int
	updates int
}

func (f *fakeKMSHealthStatusProvider) GetKMSEncryptionStatus(_ context.Context) (*operatorv1.KMSEncryptionStatus, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.status == nil {
		return &operatorv1.KMSEncryptionStatus{}, nil
	}
	return f.status.DeepCopy(), nil
}

func (f *fakeKMSHealthStatusProvider) ApplyKMSEncryptionStatus(_ context.Context, _ string, _ *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	return nil
}

func (f *fakeKMSHealthStatusProvider) UpdateKMSEncryptionStatus(_ context.Context, mutate func(*operatorv1.KMSEncryptionStatus)) error {
	f.updates++
	if f.status == nil {
		f.status = &operatorv1.KMSEncryptionStatus{}
	}
	mutate(f.status)
	return nil
}

var _ kms.EncryptionStatusProvider = &fakeKMSHealthStatusProvider{}

func kmsConfigWithPlugins() *encryptiondata.Config {
	return &encryptiondata.Config{
		KMSPlugins: map[string]kms.KMSPluginConfig{
			"1": {Type: kms.VaultKMSProvider},
		},
	}
}

func applyKMSHealth(t *testing.T, c *conditionController, config *encryptiondata.Config) {
	t.Helper()
	if err := c.reconcileKMSHealthConditions(context.Background(), config); err != nil {
		t.Fatal(err)
	}
}

func TestConditionControllerKMSHealthProgresses(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					RemoteKeyID:     "remote-b",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionTrue, kmsRemoteKeysNotConvergedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
}

func TestConditionControllerKMSHealthNotDegradedBeforeTimeout(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					RemoteKeyID:     "remote-b",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{
			Conditions: []operatorv1.OperatorCondition{{
				Type:               kmsHealthProgressingCondition,
				Status:             operatorv1.ConditionTrue,
				Reason:             "KMSRemoteKeysNotConverged",
				LastTransitionTime: metav1.NewTime(now.Add(-(kmsHealthDegradedTimeout - time.Minute))),
			}},
		},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionTrue, kmsRemoteKeysNotConvergedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
}

func TestConditionControllerKMSHealthDegradedAfterTimeout(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					RemoteKeyID:     "remote-b",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{
			Conditions: []operatorv1.OperatorCondition{{
				Type:               kmsHealthProgressingCondition,
				Status:             operatorv1.ConditionTrue,
				Reason:             "KMSRemoteKeysNotConverged",
				LastTransitionTime: metav1.NewTime(now.Add(-kmsHealthDegradedTimeout)),
			}},
		},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionTrue, kmsRemoteKeysNotConvergedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionTrue, kmsRemoteKeysNotConvergedReason)
}

func TestConditionControllerKMSHealthPreservesConditionsOnStatusError(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)
	progressingSince := metav1.NewTime(now.Add(-kmsHealthDegradedTimeout))

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{
			Conditions: []operatorv1.OperatorCondition{
				{
					Type:               kmsHealthProgressingCondition,
					Status:             operatorv1.ConditionTrue,
					Reason:             "KMSRemoteKeysNotConverged",
					LastTransitionTime: progressingSince,
				},
				{
					Type:               kmsHealthDegradedCondition,
					Status:             operatorv1.ConditionTrue,
					Reason:             "KMSRemoteKeysNotConverged",
					LastTransitionTime: progressingSince,
				},
			},
		},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        &fakeKMSHealthStatusProvider{getErr: fmt.Errorf("status unavailable")},
		clock:                           fakeClock,
	}

	if err := c.reconcileKMSHealthConditions(context.Background(), kmsConfigWithPlugins()); err == nil {
		t.Fatal("expected status provider error")
	}

	_, operatorStatus, _, err := fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	progressingCond := v1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthProgressingCondition)
	if progressingCond == nil || progressingCond.Status != operatorv1.ConditionTrue {
		t.Fatalf("expected Progressing to remain True, got %#v", progressingCond)
	}
	if !progressingCond.LastTransitionTime.Equal(&progressingSince) {
		t.Fatalf("Progressing LastTransitionTime changed: got %v want %v", progressingCond.LastTransitionTime, progressingSince)
	}
	degradedCond := v1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthDegradedCondition)
	if degradedCond == nil || degradedCond.Status != operatorv1.ConditionTrue {
		t.Fatalf("expected Degraded to remain True, got %#v", degradedCond)
	}
}

func TestConditionControllerKMSHealthClearsWithoutKMSPlugins(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)
	progressingSince := metav1.NewTime(now.Add(-kmsHealthDegradedTimeout))

	tests := []struct {
		name            string
		config          *encryptiondata.Config
		status          *operatorv1.KMSEncryptionStatus
		wantUpdates     int
		wantReportCount int
	}{
		{
			name:   "nil config clears leftover reports",
			config: nil,
			status: &operatorv1.KMSEncryptionStatus{
				HealthReports: []operatorv1.KMSPluginHealthReport{{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Hour)),
				}},
			},
			wantUpdates:     1,
			wantReportCount: 0,
		},
		{
			name:   "empty KMSPlugins clears leftover reports",
			config: &encryptiondata.Config{},
			status: &operatorv1.KMSEncryptionStatus{
				HealthReports: []operatorv1.KMSPluginHealthReport{{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Hour)),
				}},
			},
			wantUpdates:     1,
			wantReportCount: 0,
		},
		{
			name:            "nil KMSPlugins map with no reports skips update",
			config:          &encryptiondata.Config{KMSPlugins: nil},
			status:          &operatorv1.KMSEncryptionStatus{},
			wantUpdates:     0,
			wantReportCount: 0,
		},
		{
			name:            "kms never enabled skips update",
			config:          nil,
			status:          nil,
			wantUpdates:     0,
			wantReportCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &fakeKMSHealthStatusProvider{status: tt.status}

			fakeOperatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
				&operatorv1.OperatorStatus{
					Conditions: []operatorv1.OperatorCondition{
						{
							Type:               kmsHealthProgressingCondition,
							Status:             operatorv1.ConditionTrue,
							Reason:             "KMSRemoteKeysNotConverged",
							LastTransitionTime: progressingSince,
						},
						{
							Type:               kmsHealthDegradedCondition,
							Status:             operatorv1.ConditionTrue,
							Reason:             "KMSRemoteKeysNotConverged",
							LastTransitionTime: progressingSince,
						},
					},
				},
				nil,
			)

			c := &conditionController{
				controllerInstanceName:          "test-EncryptionCondition",
				controllerKMSHealthInstanceName: "test-KMSHealthCondition",
				operatorClient:                  fakeOperatorClient,
				provider:                        newTestProvider(nil),
				preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
				encryptionStatusProvider:        provider,
				clock:                           fakeClock,
			}

			if err := c.reconcileKMSHealthConditions(context.Background(), tt.config); err != nil {
				t.Fatal(err)
			}

			if provider.gets != 1 {
				t.Fatalf("expected GetKMSEncryptionStatus once, got %d gets", provider.gets)
			}
			if provider.updates != tt.wantUpdates {
				t.Fatalf("expected %d updates, got %d", tt.wantUpdates, provider.updates)
			}
			gotReports := 0
			if provider.status != nil {
				gotReports = len(provider.status.HealthReports)
			}
			if gotReports != tt.wantReportCount {
				t.Fatalf("expected %d HealthReports, got %d", tt.wantReportCount, gotReports)
			}
			assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
			assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
		})
	}
}

func TestConditionControllerKMSHealthMissingReportsProgresses(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionTrue, kmsHealthReportsMissingReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
}

func TestConditionControllerKMSHealthPrunesStaleReports(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-old",
					KeyID:           "1",
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-health.DefaultReportPruneTTL)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	if got := len(provider.status.HealthReports); got != 2 {
		t.Fatalf("expected stale report pruned, got %d reports", got)
	}
	for _, report := range provider.status.HealthReports {
		if report.NodeName == "node-old" {
			t.Fatalf("stale report still present: %#v", report)
		}
	}
	// Replaced-node stale reports are pruned without degrading when the remainder is converged.
	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
}

func TestConditionControllerKMSHealthProbeFailedDegrades(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					Status:          operatorv1.KMSPluginHealthStatusHealthy,
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					Status:          operatorv1.KMSPluginHealthStatusUnhealthy,
					Detail:          "permission denied",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionTrue, kmsProbeFailedReason)
}

func TestConditionControllerKMSHealthConvergedAsExpected(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	provider := &fakeKMSHealthStatusProvider{
		status: &operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{
					NodeName:        "node-a",
					KeyID:           "1",
					Status:          operatorv1.KMSPluginHealthStatusHealthy,
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
				{
					NodeName:        "node-b",
					KeyID:           "1",
					Status:          operatorv1.KMSPluginHealthStatusHealthy,
					RemoteKeyID:     "remote-a",
					LastCheckedTime: metav1.NewTime(now.Add(-time.Minute)),
				},
			},
		},
	}

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider(nil),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		encryptionStatusProvider:        provider,
		clock:                           fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthProgressingCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
	assertCondition(t, fakeOperatorClient, kmsHealthDegradedCondition, operatorv1.ConditionFalse, kmsAsExpectedReason)
}

func TestConditionControllerSyncKMSHealthErrorDoesNotBlockEncrypted(t *testing.T) {
	// Encrypted is computed before KMS health; a health error must still publish Encrypted
	// with Status set (ApplyOperatorStatus panics on missing status) and must not publish
	// health False (would reset Progressing LTT).
	cfg := encryptiondatatesting.CreateEncryptionCfgNoWriteKey("1", "NjFkZWY5NjRmYjk2N2Y1ZDdjNDRhMmFmOGRhYjY4NjU=", "secrets")
	cfg.KMSPlugins = map[string]kms.KMSPluginConfig{
		"1": {Type: kms.VaultKMSProvider},
	}
	encSecret := createEncryptionCfgSecret(t, "test", "1", cfg)
	progressingSince := metav1.NewTime(time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC))

	fakeOperatorClient := &statusValidatingOperatorClient{
		OperatorClient: v1helpers.NewFakeOperatorClient(
			&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
			&operatorv1.OperatorStatus{
				Conditions: []operatorv1.OperatorCondition{
					{
						Type:   "Encrypted",
						Status: operatorv1.ConditionTrue,
						Reason: "EncryptionCompleted",
					},
					{
						Type:               kmsHealthProgressingCondition,
						Status:             operatorv1.ConditionTrue,
						Reason:             "KMSRemoteKeysNotConverged",
						LastTransitionTime: progressingSince,
					},
				},
			},
			nil,
		),
	}

	c := &conditionController{
		controllerInstanceName:          "test-EncryptionCondition",
		controllerKMSHealthInstanceName: "test-KMSHealthCondition",
		operatorClient:                  fakeOperatorClient,
		provider:                        newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}}),
		preconditionsFulfilledFn:        alwaysFulfilledPreconditions,
		deployer:                        &fakeEncryptionDeployer{secret: encSecret, converged: true},
		secretClient:                    fake.NewSimpleClientset().CoreV1(),
		encryptionSecretSelector:        metav1.ListOptions{},
		encryptionStatusProvider:        &fakeKMSHealthStatusProvider{getErr: fmt.Errorf("status unavailable")},
		clock:                           clocktesting.NewFakePassiveClock(time.Now()),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sync panicked applying Encrypted without status on KMS health error: %v", r)
		}
	}()

	err := c.sync(context.Background(), factory.NewSyncContext("test", events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))))
	if err == nil {
		t.Fatal("expected KMS health status error")
	}

	_, operatorStatus, _, err := fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	encrypted := v1helpers.FindOperatorCondition(operatorStatus.Conditions, "Encrypted")
	if encrypted == nil || encrypted.Status == "" {
		t.Fatalf("expected Encrypted to be published with status despite KMS health error, got %#v", encrypted)
	}
	progressing := v1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthProgressingCondition)
	if progressing == nil || progressing.Status != operatorv1.ConditionTrue {
		t.Fatalf("expected Progressing preserved, got %#v", progressing)
	}
	if !progressing.LastTransitionTime.Equal(&progressingSince) {
		t.Fatalf("Progressing LTT changed: got %v want %v", progressing.LastTransitionTime, progressingSince)
	}
}

func assertCondition(t *testing.T, client v1helpers.OperatorClient, conditionType string, status operatorv1.ConditionStatus, reason string) {
	t.Helper()
	_, operatorStatus, _, err := client.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	cond := v1helpers.FindOperatorCondition(operatorStatus.Conditions, conditionType)
	if cond == nil {
		t.Fatalf("missing condition %q", conditionType)
	}
	if cond.Status != status {
		t.Fatalf("%s status = %q, want %q", conditionType, cond.Status, status)
	}
	if reason != "" && cond.Reason != reason {
		t.Fatalf("%s reason = %q, want %q", conditionType, cond.Reason, reason)
	}
}
