package admissiontimeout

import (
	"context"
	"fmt"
	"strings"
	"testing"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/admission"
)

type admitFunc func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error

type dummyAdmit struct {
	admitFn admitFunc
}

func (p dummyAdmit) Handles(operation admission.Operation) bool {
	return true
}

func (p dummyAdmit) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return p.admitFn(ctx, a, o)
}

func (p dummyAdmit) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	return p.admitFn(ctx, a, o)
}

func TestTimeoutAdmission(t *testing.T) {
	utilruntime.ReallyCrash = false

	tests := []struct {
		name string

		admissionPlugin func() (admit admitFunc, stopCh chan struct{})
		expectedError   string
	}{
		{
			name: "stops on time",
			admissionPlugin: func() (admitFunc, chan struct{}) {
				stopCh := make(chan struct{})
				return func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
					<-stopCh
					return nil
				}, stopCh
			},
			expectedError: `fake-name" failed to complete`,
		},
		{
			name: "stops on success",
			admissionPlugin: func() (admitFunc, chan struct{}) {
				stopCh := make(chan struct{})
				return func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
					return fmt.Errorf("fake failure to finish")
				}, stopCh
			},
			expectedError: "fake failure to finish",
		},
		{
			name: "no crash on panic",
			admissionPlugin: func() (admitFunc, chan struct{}) {
				stopCh := make(chan struct{})
				return func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
					panic("fail!")
				}, stopCh
			},
			expectedError: "default to ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admitFn, stopCh := test.admissionPlugin()
			defer close(stopCh)

			fakePlugin := dummyAdmit{admitFn: admitFn}
			decorator := WithTimeout(fakePlugin, "fake-name")

			actualErr := decorator.(admission.MutationInterface).Admit(context.TODO(), nil, nil)
			validateErr(t, actualErr, test.expectedError)

			actualErr = decorator.(admission.ValidationInterface).Validate(context.TODO(), nil, nil)
			validateErr(t, actualErr, test.expectedError)
		})
	}
}

func validateErr(t *testing.T, actualErr error, expectedError string) {
	t.Helper()
	switch {
	case actualErr == nil && len(expectedError) != 0:
		t.Fatal(expectedError)
	case actualErr == nil && len(expectedError) == 0:
	case actualErr != nil && len(expectedError) == 0:
		t.Fatal(actualErr)
	case actualErr != nil && !strings.Contains(actualErr.Error(), expectedError):
		t.Fatal(actualErr)
	}
}
