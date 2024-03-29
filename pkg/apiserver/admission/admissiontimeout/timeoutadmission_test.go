package admissiontimeout

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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
	tests := []struct {
		name string

		timeout         time.Duration
		admissionPlugin func() (admit admitFunc, stopCh chan struct{})
		expectedError   string
	}{
		{
			name:    "stops on time",
			timeout: 50 * time.Millisecond,
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
			name:    "stops on success",
			timeout: 500 * time.Millisecond,
			admissionPlugin: func() (admitFunc, chan struct{}) {
				stopCh := make(chan struct{})
				return func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
					return fmt.Errorf("fake failure to finish")
				}, stopCh
			},
			expectedError: "fake failure to finish",
		},
		{
			name:    "no crash on panic",
			timeout: 500 * time.Millisecond,
			admissionPlugin: func() (admitFunc, chan struct{}) {
				stopCh := make(chan struct{})
				return func(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
					panic("fail!")
				}, stopCh
			},
			expectedError: "admission panic'd: fail!",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/Admit", test.name), func(t *testing.T) {
			admitFn, stopCh := test.admissionPlugin()
			defer close(stopCh)

			fakePlugin := dummyAdmit{admitFn: admitFn}
			decorator := AdmissionTimeout{Timeout: test.timeout}
			decoratedPlugin := decorator.WithTimeout(fakePlugin, "fake-name")

			var actualErr error
			func() {
				defer func() {
					// if there is a panic we expect the timeout delegator to
					// propagate the panic error.
					if err := recover(); err != nil {
						switch t := err.(type) {
						case error:
							actualErr = t
						}
					}
				}()
				actualErr = decoratedPlugin.(admission.MutationInterface).Admit(context.TODO(), nil, nil)
			}()

			validateErr(t, actualErr, test.expectedError)
		})
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/Validate", test.name), func(t *testing.T) {
			admitFn, stopCh := test.admissionPlugin()
			defer close(stopCh)

			fakePlugin := dummyAdmit{admitFn: admitFn}
			decorator := AdmissionTimeout{Timeout: test.timeout}
			decoratedPlugin := decorator.WithTimeout(fakePlugin, "fake-name")

			var actualErr error
			func() {
				defer func() {
					if err := recover(); err != nil {
						switch t := err.(type) {
						case error:
							actualErr = t
						}
					}
				}()
				actualErr = decoratedPlugin.(admission.ValidationInterface).Validate(context.TODO(), nil, nil)
			}()

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
