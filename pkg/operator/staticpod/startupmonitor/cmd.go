package startupmonitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/config/client"
	"github.com/openshift/library-go/pkg/operator/staticpod/internal/flock"
)

// ReadinessChecker is a contract between the startup monitor and operators.
type ReadinessChecker interface {
	IsReady(ctx context.Context, revision int) (ready bool, reason string, message string, err error)
}

// WantsRestConfig an optional interface used for setting rest config for Kube API
type WantsRestConfig interface {
	SetRestConfig(config *rest.Config)
}

type Options struct {
	// Revision identifier for this particular installation instance
	Revision int

	// FallbackTimeout specifies a timeout after which the monitor starts the fall back procedure
	FallbackTimeout time.Duration

	// ResourceDir directory that holds all files supporting the static pod manifest
	ResourceDir string

	// ManifestDir directory for the static pod manifest
	ManifestDir string

	// TargetName identifies operand used to construct the final file name when reading the current and previous manifests
	TargetName string

	// KubeConfig file for authn/authz against Kube API
	KubeConfig string

	// installerLock blocks the installer from running in parallel. The monitor will run
	// every iteration of the probe interval with this lock taken.
	InstallerLockFile string

	// Check is the readiness step.
	Check ReadinessChecker
}

func NewCommand(check ReadinessChecker) *cobra.Command {
	o := Options{
		Check: check,
	}

	cmd := &cobra.Command{
		Use:   "startup-monitor",
		Short: "Monitors the provided static pod revision and if it proves unhealthy rolls back to the previous revision.",
		Run: func(cmd *cobra.Command, args []string) {
			klog.V(1).Info(cmd.Flags())
			klog.V(1).Info(spew.Sdump(o))

			if err := o.Validate(); err != nil {
				klog.Exit(err)
			}

			shutdownCtx := setupSignalContext(context.TODO())

			m := newMonitor(o.Check.IsReady).
				withRevision(o.Revision).
				withManifestPath(o.ManifestDir).
				withTargetName(o.TargetName).
				withProbeInterval(time.Second).
				withTimeout(o.FallbackTimeout)

			fb := newStaticPodFallback().
				withRevision(o.Revision).
				withManifestPath(o.ManifestDir).
				withStaticPodResourcesPath(o.ResourceDir).
				withTargetName(o.TargetName)

			if len(o.KubeConfig) > 0 {
				clientConfig, err := client.GetKubeConfigOrInClusterConfig(o.KubeConfig, nil)
				if err != nil {
					klog.Fatal(err)
				}

				restConfig := rest.CopyConfig(clientConfig)
				if c, ok := o.Check.(WantsRestConfig); ok {
					c.SetRestConfig(restConfig)
				}
			}

			// use flock based locking with installer. We will try to release the lock cleanly, but the
			// Linux kernel will release the lock in case we hit the unavoidable race. In worst case,
			// we leave the lock file, but avoid racing about the startup-monitor static pod manifest.
			var installerLock Locker = nullMutex{}
			if len(o.InstallerLockFile) > 0 {
				installerLock = flock.New(o.InstallerLockFile)
			}

			suicider := &o

			if err := run(shutdownCtx, installerLock, m, fb, suicider); err != nil {
				klog.Fatal(err)
			}
		},
	}

	o.AddFlags(cmd.Flags())
	return cmd
}

func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.KubeConfig, "kubeconfig", o.KubeConfig, "kubeconfig file or empty")
	fs.IntVar(&o.Revision, "revision", o.Revision, "identifier for this particular installation instance")
	fs.DurationVar(&o.FallbackTimeout, "fallback-timeout-duration", 33*time.Second, "maximum time in seconds to wait for the operand to become healthy (default 33s)")
	fs.StringVar(&o.ResourceDir, "resource-dir", o.ResourceDir, "directory that holds all files supporting the static pod manifests")
	fs.StringVar(&o.ManifestDir, "manifests-dir", o.ManifestDir, "directory for the static pod manifest")
	fs.StringVar(&o.TargetName, "target-name", o.TargetName, "identifies operand used to construct the final file name when reading the current and previous manifests")
	fs.StringVar(&o.ResourceDir, "installer-lock-file", o.InstallerLockFile, "file path for the installer flock based lock file")
}

func (o *Options) Validate() error {
	if o.FallbackTimeout == 0 {
		return fmt.Errorf("--fallback-timeout-duration cannot be 0")
	}
	if len(o.ResourceDir) == 0 {
		return fmt.Errorf("--resource-dir is required")
	}
	if len(o.ManifestDir) == 0 {
		return fmt.Errorf("--manifests-dir is required")
	}
	if len(o.TargetName) == 0 {
		return fmt.Errorf("--target-name is required")
	}
	return nil
}

type suicider interface {
	// suicide terminates this process, while trying to release the installer lock cleanly if it can.
	//
	// suicide does not return.
	suicide(installerLock Locker)
}

func (o *Options) suicide(installerLock Locker) {
	if err := os.Remove(filepath.Join(o.ManifestDir, fmt.Sprintf("%s-startup-monitor.yaml", o.TargetName))); err != nil && !os.IsNotExist(err) {
		installerLock.Unlock()
		klog.Exit("Failed to suicide: %v", err)
	}
	installerLock.Unlock()
	klog.Info("Waiting for SIGTERM...")
	for {
	}
}

// run runs the monitor, initiates fallback or mark revision as good and suicides.
//
// run only returns on error or when ctx is done. Otherwise, it suicides the process.
func run(ctx context.Context, installerLock Locker, m Monitor, fb fallback, s suicider) error {
	ready, reason, message, err := m.Run(ctx, installerLock)
	if err != nil {
		return err
	}

	// fallback or leave ready target running

	if ready {
		if err := fb.markRevisionGood(); err != nil {
			return err
		}
	} else {
		if err := fb.fallbackToPreviousRevision(reason, message); err != nil {
			return err
		}
	}

	// NOTE: here installLock is taken

	select {
	case <-ctx.Done():
		installerLock.Unlock()
		return nil
	default:
	}

	// suicide
	s.suicide(installerLock)
	return nil
}
