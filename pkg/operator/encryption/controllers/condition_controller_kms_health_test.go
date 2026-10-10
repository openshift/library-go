package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type fakeKMSHealthStatusProvider struct {
	status *operatorv1.KMSEncryptionStatus
	getErr error
	gets   int
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
	progressing, degraded, err := c.kmsHealthConditions(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	status := applyoperatorv1.OperatorStatus().WithConditions(progressing, degraded)
	if err := c.operatorClient.ApplyOperatorStatus(context.Background(), c.controllerInstanceName, status); err != nil {
		t.Fatal(err)
	}
}

func TestConditionControllerKMSHealthPrunesAndProgresses(t *testing.T) {
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
		controllerInstanceName:   "test-EncryptionCondition",
		operatorClient:           fakeOperatorClient,
		provider:                 newTestProvider(nil),
		preconditionsFulfilledFn: alwaysFulfilledPreconditions,
		encryptionStatusProvider: provider,
		clock:                    fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	if got := len(provider.status.HealthReports); got != 2 {
		t.Fatalf("expected stale report pruned, got %d reports", got)
	}

	assertCondition(t, fakeOperatorClient, kmsHealthReportsProgressingCondition, operatorv1.ConditionTrue, "HealthReportsNotConverged")
	assertCondition(t, fakeOperatorClient, kmsHealthReportsDegradedCondition, operatorv1.ConditionFalse, "")
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
				Type:               kmsHealthReportsProgressingCondition,
				Status:             operatorv1.ConditionTrue,
				Reason:             "HealthReportsNotConverged",
				LastTransitionTime: metav1.NewTime(now.Add(-kmsHealthReportsDegradedTimeout)),
			}},
		},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:   "test-EncryptionCondition",
		operatorClient:           fakeOperatorClient,
		provider:                 newTestProvider(nil),
		preconditionsFulfilledFn: alwaysFulfilledPreconditions,
		encryptionStatusProvider: provider,
		clock:                    fakeClock,
	}

	applyKMSHealth(t, c, kmsConfigWithPlugins())

	assertCondition(t, fakeOperatorClient, kmsHealthReportsProgressingCondition, operatorv1.ConditionTrue, "HealthReportsNotConverged")
	assertCondition(t, fakeOperatorClient, kmsHealthReportsDegradedCondition, operatorv1.ConditionTrue, "HealthReportsNotConverged")
}

func TestConditionControllerKMSHealthPreservesConditionsOnStatusError(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)
	progressingSince := metav1.NewTime(now.Add(-30 * time.Minute))

	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
		&operatorv1.OperatorStatus{
			Conditions: []operatorv1.OperatorCondition{
				{
					Type:               kmsHealthReportsProgressingCondition,
					Status:             operatorv1.ConditionTrue,
					Reason:             "HealthReportsNotConverged",
					LastTransitionTime: progressingSince,
				},
				{
					Type:               kmsHealthReportsDegradedCondition,
					Status:             operatorv1.ConditionTrue,
					Reason:             "HealthReportsNotConverged",
					LastTransitionTime: progressingSince,
				},
			},
		},
		nil,
	)

	c := &conditionController{
		controllerInstanceName:   "test-EncryptionCondition",
		operatorClient:           fakeOperatorClient,
		provider:                 newTestProvider(nil),
		preconditionsFulfilledFn: alwaysFulfilledPreconditions,
		encryptionStatusProvider: &fakeKMSHealthStatusProvider{getErr: fmt.Errorf("status unavailable")},
		clock:                    fakeClock,
	}

	if _, _, err := c.kmsHealthConditions(context.Background(), kmsConfigWithPlugins()); err == nil {
		t.Fatal("expected status provider error")
	}

	_, operatorStatus, _, err := fakeOperatorClient.GetOperatorState()
	if err != nil {
		t.Fatal(err)
	}
	progressingCond := v1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthReportsProgressingCondition)
	if progressingCond == nil || progressingCond.Status != operatorv1.ConditionTrue {
		t.Fatalf("expected Progressing to remain True, got %#v", progressingCond)
	}
	if !progressingCond.LastTransitionTime.Equal(&progressingSince) {
		t.Fatalf("Progressing LastTransitionTime changed: got %v want %v", progressingCond.LastTransitionTime, progressingSince)
	}
	degradedCond := v1helpers.FindOperatorCondition(operatorStatus.Conditions, kmsHealthReportsDegradedCondition)
	if degradedCond == nil || degradedCond.Status != operatorv1.ConditionTrue {
		t.Fatalf("expected Degraded to remain True, got %#v", degradedCond)
	}
}

func TestConditionControllerKMSHealthSkipsWithoutKMSPlugins(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakePassiveClock(now)

	tests := []struct {
		name   string
		config *encryptiondata.Config
	}{
		{name: "nil config", config: nil},
		{name: "empty KMSPlugins", config: &encryptiondata.Config{}},
		{name: "nil KMSPlugins map", config: &encryptiondata.Config{KMSPlugins: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &fakeKMSHealthStatusProvider{
				status: &operatorv1.KMSEncryptionStatus{
					HealthReports: []operatorv1.KMSPluginHealthReport{{
						NodeName:        "node-a",
						KeyID:           "1",
						RemoteKeyID:     "remote-a",
						LastCheckedTime: metav1.NewTime(now.Add(-health.DefaultReportPruneTTL)),
					}},
				},
				getErr: fmt.Errorf("should not be called"),
			}

			fakeOperatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{ManagementState: operatorv1.Managed},
				&operatorv1.OperatorStatus{},
				nil,
			)

			c := &conditionController{
				controllerInstanceName:   "test-EncryptionCondition",
				operatorClient:           fakeOperatorClient,
				provider:                 newTestProvider(nil),
				preconditionsFulfilledFn: alwaysFulfilledPreconditions,
				encryptionStatusProvider: provider,
				clock:                    fakeClock,
			}

			applyKMSHealth(t, c, tt.config)

			if provider.gets != 0 {
				t.Fatalf("expected status provider not to be called, got %d gets", provider.gets)
			}
			if got := len(provider.status.HealthReports); got != 1 {
				t.Fatalf("expected reports left untouched, got %d", got)
			}
			assertCondition(t, fakeOperatorClient, kmsHealthReportsProgressingCondition, operatorv1.ConditionFalse, "")
			assertCondition(t, fakeOperatorClient, kmsHealthReportsDegradedCondition, operatorv1.ConditionFalse, "")
		})
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
