// Disposable CLI: prints what health.GenerateContainerTemplate emits, so
// the KIND harness validates the production template end-to-end.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
)

func main() {
	var (
		pluginName = flag.String("kms-plugin-name", "",
			"DNS-1123 label identifying the plugin instance (required)")
		image  = flag.String("image", "", "operator image (required)")
		cmdStr = flag.String("command", "",
			"operator binary command, comma-separated (required), e.g. /usr/bin/kms-health-monitor")
		probeInterval          = flag.Duration("probe-interval", 60*time.Second, "")
		probeIntervalUnhealthy = flag.Duration("probe-interval-unhealthy", 10*time.Second, "")
		probeTimeout           = flag.Duration("probe-timeout", 3*time.Second, "")
		writeTimeout           = flag.Duration("write-timeout", 5*time.Second, "")
		ns                     = flag.String("configmap-namespace", "",
			"operand namespace (required)")
	)
	flag.Parse()

	var cmdParts []string
	if *cmdStr != "" {
		cmdParts = strings.Split(*cmdStr, ",")
	}

	container, err := health.GenerateContainerTemplate(health.ContainerOptions{
		KMSPluginName:          *pluginName,
		OperatorImage:          *image,
		OperatorCommand:        cmdParts,
		ProbeInterval:          *probeInterval,
		ProbeIntervalUnhealthy: *probeIntervalUnhealthy,
		ProbeTimeout:           *probeTimeout,
		WriteTimeout:           *writeTimeout,
		ConfigMapNamespace:     *ns,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "render-container:", err)
		os.Exit(1)
	}

	out, err := yaml.Marshal(&container)
	if err != nil {
		fmt.Fprintln(os.Stderr, "render-container: marshal:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "render-container: write:", err)
		os.Exit(1)
	}
}
