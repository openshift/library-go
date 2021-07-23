package startupmonitor

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	operatorv1 "github.com/openshift/api/operator/v1"
)

type startupMonitorTemplate struct {
	Command         string
	TargetNamespace string
	TargetName      string
	OperatorImage   string
	Verbosity       string
}

func GeneratePodTemplate(operatorSpec *operatorv1.StaticPodOperatorSpec, command []string, targetNamespace, targetName, targetImagePullSpec string) (string, error) {
	rawStartupMonitorManifest := mustAsset("assets/startup-monitor-pod.yaml")

	var verbosity string
	switch operatorSpec.LogLevel {
	case operatorv1.Normal:
		verbosity = fmt.Sprintf(" -v=%d", 2)
	case operatorv1.Debug:
		verbosity = fmt.Sprintf(" -v=%d", 4)
	case operatorv1.Trace:
		verbosity = fmt.Sprintf(" -v=%d", 6)
	case operatorv1.TraceAll:
		verbosity = fmt.Sprintf(" -v=%d", 8)
	default:
		verbosity = fmt.Sprintf(" -v=%d", 2)
	}

	for idx, cmd := range command {
		command[idx] = fmt.Sprintf("\"%s\"", cmd)
	}

	tmplVal := startupMonitorTemplate{
		Command:         strings.Join(command, ","),
		TargetNamespace: targetNamespace,
		TargetName:      targetName,
		OperatorImage:   targetImagePullSpec,
		Verbosity:       verbosity,
	}
	tmpl, err := template.New("monitor").Parse(string(rawStartupMonitorManifest))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplVal)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
