// Command monitor is the throwaway KIND-stage binary that bundles
// library-go's health.NewCommand(). Production builds come from the
// OpenShift operator repos; this main exists only so the KIND harness
// has something to put in a Dockerfile.
package main

import (
	"fmt"
	"os"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
)

func main() {
	ctx := genericapiserver.SetupSignalContext()
	cmd := health.NewCommand(ctx)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		klog.Flush()
		os.Exit(1)
	}
	klog.Flush()
}
