package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/openshift/library-go/pkg/network/commatrix"
	clientutil "github.com/openshift/library-go/pkg/network/commatrix/client"
	"github.com/openshift/library-go/pkg/network/commatrix/ss"
	"github.com/openshift/library-go/pkg/network/commatrix/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	var (
		destDir           string
		format            string
		envStr            string
		customEntriesPath string
		printFn           func(m *types.ComMatrix) ([]byte, error)
	)

	flag.StringVar(&destDir, "destDir", "communication-matrix", "Output files dir")
	flag.StringVar(&format, "format", "csv", "Desired format (json,yaml,csv)")
	flag.StringVar(&envStr, "env", "baremetal", "Cluster environment (baremetal/aws)")
	flag.StringVar(&customEntriesPath, "customEntriesPath", "", "Add custom entries from a JSON file to the matrix")

	flag.Parse()

	switch format {
	case "json":
		printFn = types.ToJSON
	case "csv":
		printFn = types.ToCSV
	case "yaml":
		printFn = types.ToYAML
	default:
		panic(fmt.Sprintf("invalid format: %s. Please specify json, csv, or yaml.", format))
	}

	kubeconfig, ok := os.LookupEnv("KUBECONFIG")
	if !ok {
		panic("must set the KUBECONFIG environment variable")
	}

	var env commatrix.Env
	switch envStr {
	case "baremetal":
		env = commatrix.Baremetal
	case "aws":
		env = commatrix.AWS
	default:
		panic(fmt.Sprintf("invalid cluster environment: %s", envStr))
	}

	// TODO: customEntries file
	mat, err := commatrix.New(kubeconfig, customEntriesPath, env)
	if err != nil {
		panic(fmt.Sprintf("failed to create the communication matrix: %s", err))
	}

	res, err := printFn(mat)
	if err != nil {
		panic(err)
	}

	comMatrixFileName := filepath.Join(destDir, fmt.Sprintf("communication-matrix.%s", format))
	err = os.WriteFile(comMatrixFileName, []byte(string(res)), 0644)
	if err != nil {
		panic(err)
	}

	cs, err := clientutil.New(kubeconfig)
	if err != nil {
		panic(err)
	}

	tcpFile, err := os.OpenFile(path.Join(destDir, "raw-ss-tcp"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer tcpFile.Close()

	udpFile, err := os.OpenFile(path.Join(destDir, "raw-ss-udp"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer udpFile.Close()

	nodesList, err := cs.Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err)
	}

	nodesComDetails := []types.ComDetails{}
	for _, n := range nodesList.Items {
		// TODO: can be improved with go routines
		cds, err := ss.CreateComDetailsFromNode(cs, &n, tcpFile, udpFile)
		if err != nil {
			panic(err)
		}

		nodesComDetails = append(nodesComDetails, cds...)
	}
	cleanedComDetails := types.RemoveDups(nodesComDetails)
	ssComMat := types.ComMatrix{Matrix: cleanedComDetails}

	res, err = printFn(&ssComMat)
	if err != nil {
		panic(err)
	}

	ssMatrixFileName := filepath.Join(destDir, fmt.Sprintf("ss-generated-matrix.%s", format))
	err = os.WriteFile(ssMatrixFileName, []byte(string(res)), 0644)
	if err != nil {
		panic(err)
	}

	diff := ""
	for _, cd1 := range mat.Matrix {
		found := false
		for _, cd2 := range ssComMat.Matrix {
			if cd1.Equals(cd2) {
				found = true
				break
			}
		}
		if !found {
			diff += fmt.Sprintf("+ %s\n", cd1)
			continue
		}
		diff += fmt.Sprintf("%s\n", cd1)
	}

	for _, cd1 := range ssComMat.Matrix {
		found := false
		for _, cd2 := range mat.Matrix {
			if cd1.Equals(cd2) {
				found = true
				break
			}
		}
		if !found {
			diff += fmt.Sprintf("- %s\n", cd1)
			continue
		}
		diff += fmt.Sprintf("%s\n", cd1)
	}

	err = os.WriteFile(filepath.Join(destDir, "matrix-diff-ss"),
		[]byte(diff),
		0644)
	if err != nil {
		panic(err)
	}
}
