package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// ContainerOptions are the per-caller knobs for GenerateContainerTemplate.
// KMSPluginName is the cohering parameter; distinct names produce
// non-colliding sidecars so multiple plugins can be observed in one pod.
type ContainerOptions struct {
	// Must be a DNS-1123 label; suffixed onto container/volume/CM names.
	KMSPluginName string

	OperatorImage   string
	OperatorCommand []string

	ProbeInterval          time.Duration
	ProbeIntervalUnhealthy time.Duration
	ProbeTimeout           time.Duration
	WriteTimeout           time.Duration

	ConfigMapNamespace string
}

// GenerateContainerTemplate renders the kms-health-monitor sidecar.
// Caller must add a matching Volume named kms-plugin-socket-<KMSPluginName>
// to PodSpec.Volumes. The deprecated single-plugin
// AddKMSPluginVolumeAndMountToPodSpec helper is intentionally not used.
func GenerateContainerTemplate(opts ContainerOptions) (corev1.Container, error) {
	if err := opts.validate(); err != nil {
		return corev1.Container{}, err
	}

	rawManifest := mustAsset("assets/kms-health-container.yaml")

	funcs := template.FuncMap{
		"toJson": func(v any) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	}

	tmpl, err := template.New("kms-health-container").Funcs(funcs).Parse(string(rawManifest))
	if err != nil {
		return corev1.Container{}, fmt.Errorf("parse asset template: %w", err)
	}

	values := struct {
		KMSPluginName          string
		OperatorImage          string
		Command                []string
		ProbeInterval          string
		ProbeIntervalUnhealthy string
		ProbeTimeout           string
		WriteTimeout           string
		ConfigMapNamespace     string
	}{
		KMSPluginName:          opts.KMSPluginName,
		OperatorImage:          opts.OperatorImage,
		Command:                opts.OperatorCommand,
		ProbeInterval:          opts.ProbeInterval.String(),
		ProbeIntervalUnhealthy: opts.ProbeIntervalUnhealthy.String(),
		ProbeTimeout:           opts.ProbeTimeout.String(),
		WriteTimeout:           opts.WriteTimeout.String(),
		ConfigMapNamespace:     opts.ConfigMapNamespace,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, values); err != nil {
		return corev1.Container{}, fmt.Errorf("execute template: %w", err)
	}

	var container corev1.Container
	if err := yaml.Unmarshal(buf.Bytes(), &container); err != nil {
		return corev1.Container{}, fmt.Errorf("parse rendered container: %w", err)
	}
	return container, nil
}

func (o ContainerOptions) validate() error {
	if errs := validation.IsDNS1123Label(o.KMSPluginName); len(errs) > 0 {
		return fmt.Errorf("KMSPluginName %q is not a valid DNS-1123 label: %s",
			o.KMSPluginName, strings.Join(errs, "; "))
	}
	if o.OperatorImage == "" {
		return fmt.Errorf("OperatorImage is required")
	}
	if len(o.OperatorCommand) == 0 {
		return fmt.Errorf("OperatorCommand must have at least one element")
	}
	if o.ProbeInterval <= 0 {
		return fmt.Errorf("ProbeInterval must be positive")
	}
	if o.ProbeIntervalUnhealthy <= 0 {
		return fmt.Errorf("ProbeIntervalUnhealthy must be positive")
	}
	if o.ProbeTimeout <= 0 {
		return fmt.Errorf("ProbeTimeout must be positive")
	}
	if o.WriteTimeout <= 0 {
		return fmt.Errorf("WriteTimeout must be positive")
	}
	if o.ConfigMapNamespace == "" {
		return fmt.Errorf("ConfigMapNamespace is required")
	}
	return nil
}
