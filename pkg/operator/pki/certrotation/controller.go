package certrotation

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
)

// contentionWindow is how long conflicts on the same artifact may persist
// before the controller escalates them to ErrWriterContention and reports
// Degraded: two processes are actively fighting over an artifact.
const contentionWindow = 5 * time.Minute

// controller wraps a Reconciler in a factory.Controller. It derives its own
// filtered informers from Options.Informers, resyncs every minute (v1
// parity), schedules AddAfter at the Reconciler's NextCheck boundary,
// subscribes to DynamicHostnames changes, and applies the reporting policy
// per target.
type controller struct {
	reconciler *Reconciler
	rotation   Rotation
	reporter   StatusReporter
	// hostnameSubscriptions are the DynamicHostnames sources of the
	// rotation's targets, subscribed for requeue triggering.
	hostnameSubscriptions []<-chan struct{}
	// conflictsSince tracks when conflicts on an artifact were first seen,
	// for the ErrWriterContention escalation.
	conflictsSince map[ArtifactRef]time.Time
}

// NewController wraps a Reconciler for the given Rotation in a
// factory.Controller. Options.Informers is required: the controller derives
// the shared namespace informers from it and filters events to exactly the
// Rotation's objects. Call this before starting the informer factories.
//
// The controller name passed to ToController is "CertRotationController",
// matching v1; do not change it without migrating the operator conditions
// that key on it.
func NewController(rotation Rotation, opts Options) (factory.Controller, error) {
	c, err := newController(rotation, opts)
	if err != nil {
		return nil, err
	}
	return c.toFactoryController(opts)
}

// newController validates and builds the controller implementation.
func newController(rotation Rotation, opts Options) (*controller, error) {
	if err := rotation.Validate(); err != nil {
		return nil, err
	}
	if err := opts.validate(true); err != nil {
		return nil, err
	}
	if err := validateInformerSource(rotation, opts.Informers); err != nil {
		return nil, err
	}

	reconciler, err := NewReconciler(rotation, opts)
	if err != nil {
		return nil, err
	}

	c := &controller{
		reconciler:     reconciler,
		rotation:       rotation,
		reporter:       opts.Reporter,
		conflictsSince: map[ArtifactRef]time.Time{},
	}

	// Subscribe to every DynamicHostnames source so hostname changes
	// requeue the sync.
	seen := map[*DynamicHostnames]struct{}{}
	for i := range rotation.Targets {
		switch cert := rotation.Targets[i].Cert.(type) {
		case ServingCert:
			if dynamic, ok := cert.Hostnames.(*DynamicHostnames); ok {
				if _, dup := seen[dynamic]; !dup {
					seen[dynamic] = struct{}{}
					c.hostnameSubscriptions = append(c.hostnameSubscriptions, dynamic.Subscribe())
				}
			}
		case PeerCert:
			if dynamic, ok := cert.Hostnames.(*DynamicHostnames); ok {
				if _, dup := seen[dynamic]; !dup {
					seen[dynamic] = struct{}{}
					c.hostnameSubscriptions = append(c.hostnameSubscriptions, dynamic.Subscribe())
				}
			}
		}
	}

	return c, nil
}

// toFactoryController wraps the implementation in a factory.Controller.
func (c *controller) toFactoryController(opts Options) (factory.Controller, error) {
	informers := c.rotationInformers(opts)
	builder := factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.sync).
		WithFilteredEventsInformers(c.filterEvents, informers...)
	if len(c.hostnameSubscriptions) > 0 {
		builder = builder.WithPostStartHooks(c.hostnameRequeueHook)
	}
	return builder.ToController(
		"CertRotationController", // do not change: operator conditions key on this name (v1 parity)
		opts.Recorder.WithComponentSuffix("cert-rotation-controller"),
	), nil
}

// rotationInformers derives the Rotation's informers: the secrets and
// configmaps shared informers of every involved namespace, deduplicated,
// with events filtered to the Rotation's own objects.
func (c *controller) rotationInformers(opts Options) []factory.Informer {
	seenNamespaces := map[string]struct{}{
		c.rotation.Signer.Namespace: {},
		c.rotation.Bundle.Namespace: {},
	}
	for i := range c.rotation.Targets {
		seenNamespaces[c.rotation.Targets[i].Location.Namespace] = struct{}{}
	}

	informers := make([]factory.Informer, 0, 2*len(seenNamespaces))
	for ns := range seenNamespaces {
		informers = append(informers,
			opts.Informers.InformersFor(ns).Core().V1().Secrets().Informer(),
			opts.Informers.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
		)
	}
	return informers
}

// filterEvents admits only the Rotation's own objects.
func (c *controller) filterEvents(obj any) bool {
	switch typed := obj.(type) {
	case *corev1.Secret:
		if typed.Namespace == c.rotation.Signer.Namespace && typed.Name == c.rotation.Signer.Name {
			return true
		}
		for i := range c.rotation.Targets {
			if typed.Namespace == c.rotation.Targets[i].Location.Namespace && typed.Name == c.rotation.Targets[i].Location.Name {
				return true
			}
		}
		return false
	case *corev1.ConfigMap:
		return typed.Namespace == c.rotation.Bundle.Namespace && typed.Name == c.rotation.Bundle.Name
	default:
		return true
	}
}

// sync runs one reconcile pass and applies the requeue and reporting policy.
func (c *controller) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	result, err := c.reconciler.Reconcile(ctx)

	// Schedule the next check at the earliest decision boundary.
	if !result.NextCheck.IsZero() {
		if delay := time.Until(result.NextCheck); delay > 0 {
			syncCtx.Queue().AddAfter(factory.DefaultQueueKey, delay)
		}
	}

	// Per-target reporting.
	if c.reporter != nil {
		for i := range c.rotation.Targets {
			target := c.rotation.Targets[i]
			targetErr := result.TargetErrors[target.Name]
			if targetErr == nil {
				c.clearContention(target.Name)
				if _, reportErr := c.reporter.Report(ctx, target.Name, nil); reportErr != nil {
					return fmt.Errorf("reporting status for target %s: %w", target.Name, reportErr)
				}
				continue
			}
			if reportErr := c.targetReportError(ctx, target.Name, targetErr); reportErr != nil {
				// A failed report must not skip reporting for the remaining
				// targets.
				klog.Errorf("reporting status for target %s: %v", target.Name, reportErr)
			}
		}
	}

	return err
}

// targetReportError applies the reporting policy for one failing target:
// conflicts are held back until they persist beyond the contention window,
// then escalate to ErrWriterContention; everything else reports immediately.
func (c *controller) targetReportError(ctx context.Context, targetName string, targetErr error) error {
	if !isConflict(targetErr) {
		c.clearContention(targetName)
		_, err := c.reporter.Report(ctx, targetName, targetErr)
		return err
	}

	now := time.Now()
	key := ArtifactRef{Kind: ArtifactKindTarget, Location: Location{Namespace: c.rotation.Signer.Namespace, Name: targetName}}
	firstSeen, seen := c.conflictsSince[key]
	if !seen {
		c.conflictsSince[key] = now
		return nil
	}
	if now.Sub(firstSeen) < contentionWindow {
		return nil
	}
	_, err := c.reporter.Report(ctx, targetName, fmt.Errorf("%w: conflicts on target %s since %s", ErrWriterContention, targetName, firstSeen.Format(time.RFC3339)))
	return err
}

func (c *controller) clearContention(targetName string) {
	key := ArtifactRef{Kind: ArtifactKindTarget, Location: Location{Namespace: c.rotation.Signer.Namespace, Name: targetName}}
	delete(c.conflictsSince, key)
}

// isConflict reports whether the error chain contains ErrConflict.
func isConflict(err error) bool {
	if artifactErr, ok := errors.AsType[*ArtifactError](err); ok {
		return errors.Is(artifactErr, ErrConflict)
	}
	return errors.Is(err, ErrConflict)
}

// hostnameRequeueHook pumps DynamicHostnames notifications into the sync
// queue.
func (c *controller) hostnameRequeueHook(ctx context.Context, syncCtx factory.SyncContext) error {
	for _, subscription := range c.hostnameSubscriptions {
		go func(subscription <-chan struct{}) {
			for {
				select {
				case <-subscription:
					syncCtx.Queue().Add(factory.DefaultQueueKey)
				case <-ctx.Done():
					return
				}
			}
		}(subscription)
	}
	<-ctx.Done()
	return nil
}
