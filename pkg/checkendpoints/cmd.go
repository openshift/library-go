package checkendpoints

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	operatorcontrolplaneclient "github.com/openshift/client-go/operatorcontrolplane/clientset/versioned"
	operatorcontrolplaneinformers "github.com/openshift/client-go/operatorcontrolplane/informers/externalversions"
	"k8s.io/apimachinery/pkg/version"

	"github.com/openshift/library-go/pkg/checkendpoints/controller"
	"github.com/openshift/library-go/pkg/controller/controllercmd"
)

// NewCheckEndpointsCommand returns a `check-endpoints` command that will process the
// PodNetworkConnectivityChecks found in the podNamespace that correspond to the pod
// specified via the POD_NAME env var.
func NewCheckEndpointsCommand(podNamespace, podDescription string, version version.Info) *cobra.Command {
	config := controllercmd.NewControllerCommandConfig("check-endpoints", version, func(ctx context.Context, cctx *controllercmd.ControllerContext) error {
		operatorcontrolplaneClient := operatorcontrolplaneclient.NewForConfigOrDie(cctx.KubeConfig)
		operatorcontrolplaneInformers := operatorcontrolplaneinformers.NewSharedInformerFactoryWithOptions(operatorcontrolplaneClient, 10*time.Minute, operatorcontrolplaneinformers.WithNamespace(podNamespace))
		check := controller.NewPodNetworkConnectivityCheckController(
			os.Getenv("POD_NAME"),
			podNamespace,
			operatorcontrolplaneClient.ControlplaneV1alpha1(),
			operatorcontrolplaneInformers.Controlplane().V1alpha1().PodNetworkConnectivityChecks(),
			cctx.EventRecorder,
		)
		controller.RegisterMetrics(strings.Replace(podNamespace, "-", "_", -1)+"_", podDescription)
		operatorcontrolplaneInformers.Start(ctx.Done())
		check.Run(ctx, 1)
		<-ctx.Done()
		return nil
	})
	config.DisableLeaderElection = true
	cmd := config.NewCommandWithContext(context.Background())
	cmd.Use = "check-endpoints"
	cmd.Short = "Checks that a tcp connection can be opened to one or more endpoints."
	return cmd
}
