package admissiontimeout

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/admission"
)

type pluginHandlerWithTimeout struct {
	name            string
	admissionPlugin admission.Interface
	timeout         time.Duration
}

var _ admission.ValidationInterface = &pluginHandlerWithTimeout{}
var _ admission.MutationInterface = &pluginHandlerWithTimeout{}

func (p pluginHandlerWithTimeout) Handles(operation admission.Operation) bool {
	return p.admissionPlugin.Handles(operation)
}

func (p pluginHandlerWithTimeout) Admit(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	mutatingHandler, ok := p.admissionPlugin.(admission.MutationInterface)
	if !ok {
		return nil
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, p.timeout)
	defer cancel()

	admissionDone := make(chan struct{})
	admissionErr := fmt.Errorf("default to mutation error plugin %q", p.name)
	go func() {
		defer utilruntime.HandleCrash()
		defer close(admissionDone)
		admissionErr = mutatingHandler.Admit(ctx, a, o)
	}()

	select {
	case <-admissionDone:
		if admissionErr != nil {
			return fmt.Errorf("admission plugin %q failed to complete mutation with error: %w", p.name, admissionErr)
		}
	case <-time.After(p.timeout + 100*time.Millisecond): // let the propagated context to fail first
		return errors.NewInternalError(fmt.Errorf("admission plugin %q failed to complete mutation in %v", p.name, p.timeout))
	}
	return nil
}

func (p pluginHandlerWithTimeout) Validate(ctx context.Context, a admission.Attributes, o admission.ObjectInterfaces) error {
	validatingHandler, ok := p.admissionPlugin.(admission.ValidationInterface)
	if !ok {
		return nil
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, p.timeout)
	defer cancel()

	admissionDone := make(chan struct{})
	admissionErr := fmt.Errorf("default to mutation error plugin %q", p.name)
	go func() {
		defer utilruntime.HandleCrash()
		defer close(admissionDone)
		admissionErr = validatingHandler.Validate(ctx, a, o)
	}()

	select {
	case <-admissionDone:
		if admissionErr != nil {
			return fmt.Errorf("admission plugin %q failed to complete validation with error: %w", p.name, admissionErr)
		}
	case <-time.After(p.timeout + 100*time.Millisecond): // let the propagated context to fail first
		return errors.NewInternalError(fmt.Errorf("admission plugin %q failed to complete validation in %v", p.name, p.timeout))
	}
	return nil
}
