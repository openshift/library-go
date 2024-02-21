package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/openshift/library-go/pkg/network/commatrix"
)

func main() {
	var (
		output  string
		envStr  string
		printFn func() ([]byte, error)
	)

	flag.StringVar(&output, "output", "CSV", "The desired output format (JSON,YAML,CSV)")
	flag.StringVar(&envStr, "env", "baremetal", "The environment the cluster is on (baremetal/aws)")

	flag.Parse()

	kubeconfig, ok := os.LookupEnv("KUBECONFIG")
	if !ok {
		panic("must set the KUBECONFIG environment variable")
	}

	env, exists := commatrix.EnvMap[envStr]
	if !exists {
		panic(fmt.Sprintf("invalid cluster environment: %s", envStr))
	}

	mat, err := commatrix.New(kubeconfig, "", env)
	if err != nil {
		panic(fmt.Sprintf("failed to create the communication matrix: %s", err))
	}

	switch output {
	case "JSON":
		printFn = mat.ToJSON
	case "CSV":
		printFn = mat.ToCSV
	case "YAML":
		printFn = mat.ToYAML
	default:
		panic(fmt.Sprintf("invalid output format: %s. Please specify JSON, CSV, or YAML.", output))
	}

	res, err := printFn()
	if err != nil {
		panic(err)
	}

	fmt.Println(string(res))
}
