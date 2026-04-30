package health

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/yaml"
)

const expectedContainerYAML = `
name: kms-health-monitor-aws
image: quay.io/openshift/operator:latest
command:
  - "operator"
  - "kms-health-monitor"
args:
  - --kms-socket=/var/run/kmsplugin-aws/kms.sock
  - --probe-interval=1m0s
  - --probe-interval-unhealthy=10s
  - --probe-timeout=3s
  - --write-timeout=5s
  - --output-mode=configmap
  - --configmap-namespace=openshift-kube-apiserver
  - --configmap-name=kms-health-aws
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
volumeMounts:
  - name: kms-plugin-socket-aws
    mountPath: /var/run/kmsplugin-aws
resources:
  requests:
    memory: 50Mi
    cpu: 5m
`

func validContainerOptions() ContainerOptions {
	return ContainerOptions{
		KMSPluginName:          "aws",
		OperatorImage:          "quay.io/openshift/operator:latest",
		OperatorCommand:        []string{"operator", "kms-health-monitor"},
		ProbeInterval:          60 * time.Second,
		ProbeIntervalUnhealthy: 10 * time.Second,
		ProbeTimeout:           3 * time.Second,
		WriteTimeout:           5 * time.Second,
		ConfigMapNamespace:     "openshift-kube-apiserver",
	}
}

func TestGenerateContainerTemplate(t *testing.T) {
	got, err := GenerateContainerTemplate(validContainerOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var want corev1.Container
	if err := yaml.Unmarshal([]byte(expectedContainerYAML), &want); err != nil {
		t.Fatalf("parse expected: %v", err)
	}
	if !equality.Semantic.DeepEqual(got, want) {
		t.Fatalf("rendered container does not match expected:\ngot:  %+v\nwant: %+v", got, want)
	}
}

// Drift detector: rendered args must parse against cmd.go's flag set.
func TestRenderedArgsAreValidFlags(t *testing.T) {
	c, err := GenerateContainerTemplate(validContainerOptions())
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	fs := pflag.NewFlagSet("kms-health-monitor", pflag.ContinueOnError)
	(&commandOptions{}).addFlags(fs)
	if err := fs.Parse(c.Args); err != nil {
		t.Fatalf("rendered args do not parse against cmd.go flag set: %v\nargs: %v", err, c.Args)
	}
}

// Distinct KMSPluginName must yield non-colliding container/volume/CM names.
func TestMultiplePluginsCoexist(t *testing.T) {
	a, err := GenerateContainerTemplate(ContainerOptions{
		KMSPluginName:          "aws",
		OperatorImage:          "img:1",
		OperatorCommand:        []string{"o"},
		ProbeInterval:          60 * time.Second,
		ProbeIntervalUnhealthy: 10 * time.Second,
		ProbeTimeout:           3 * time.Second,
		WriteTimeout:           5 * time.Second,
		ConfigMapNamespace:     "ns",
	})
	if err != nil {
		t.Fatalf("render aws: %v", err)
	}
	b, err := GenerateContainerTemplate(ContainerOptions{
		KMSPluginName:          "vault",
		OperatorImage:          "img:1",
		OperatorCommand:        []string{"o"},
		ProbeInterval:          60 * time.Second,
		ProbeIntervalUnhealthy: 10 * time.Second,
		ProbeTimeout:           3 * time.Second,
		WriteTimeout:           5 * time.Second,
		ConfigMapNamespace:     "ns",
	})
	if err != nil {
		t.Fatalf("render vault: %v", err)
	}

	if a.Name == b.Name {
		t.Fatalf("container names collide: %q == %q", a.Name, b.Name)
	}
	if a.VolumeMounts[0].Name == b.VolumeMounts[0].Name {
		t.Fatalf("volumeMount names collide: %q", a.VolumeMounts[0].Name)
	}
	if a.VolumeMounts[0].MountPath == b.VolumeMounts[0].MountPath {
		t.Fatalf("mountPaths collide: %q", a.VolumeMounts[0].MountPath)
	}
	// Args must contain different --configmap-name and --kms-socket values.
	if argsEqual(a.Args, b.Args) {
		t.Fatalf("args identical for distinct plugin names")
	}
}

func argsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestContainerOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ContainerOptions)
		wantSub string
	}{
		{"empty plugin name", func(o *ContainerOptions) { o.KMSPluginName = "" }, "KMSPluginName"},
		{"underscore in plugin name", func(o *ContainerOptions) { o.KMSPluginName = "aws_kms" }, "KMSPluginName"},
		{"uppercase in plugin name", func(o *ContainerOptions) { o.KMSPluginName = "AWS" }, "KMSPluginName"},
		{"empty image", func(o *ContainerOptions) { o.OperatorImage = "" }, "OperatorImage"},
		{"empty command", func(o *ContainerOptions) { o.OperatorCommand = nil }, "OperatorCommand"},
		{"zero probe-interval", func(o *ContainerOptions) { o.ProbeInterval = 0 }, "ProbeInterval"},
		{"zero probe-interval-unhealthy", func(o *ContainerOptions) { o.ProbeIntervalUnhealthy = 0 }, "ProbeIntervalUnhealthy"},
		{"zero probe-timeout", func(o *ContainerOptions) { o.ProbeTimeout = 0 }, "ProbeTimeout"},
		{"zero write-timeout", func(o *ContainerOptions) { o.WriteTimeout = 0 }, "WriteTimeout"},
		{"empty namespace", func(o *ContainerOptions) { o.ConfigMapNamespace = "" }, "ConfigMapNamespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validContainerOptions()
			tt.mutate(&opts)
			_, err := GenerateContainerTemplate(opts)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}
