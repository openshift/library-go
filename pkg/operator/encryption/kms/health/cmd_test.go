package health

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

// validOpts is the minimal fully-valid commandOptions. Every test case
// below mutates a copy of this to isolate one validation rule at a time.
func validOpts() commandOptions {
	return commandOptions{
		kmsSocket:              "/var/run/kms.sock",
		probeInterval:          60 * time.Second,
		probeIntervalUnhealthy: 10 * time.Second,
		probeTimeout:           3 * time.Second,
		writeTimeout:           5 * time.Second,
		outputMode:             outputModeConfigMap,
		configmapNamespace:     "kms-health-test",
		configmapName:          "kms-health-master-0",
		observerPodName:        "master-0",
	}
}

func TestValidate_acceptsValidOptions(t *testing.T) {
	o := validOpts()
	if err := o.validate(); err != nil {
		t.Fatalf("validate(valid): %v", err)
	}
}

func TestValidate_rejectsMissingOrZeroFields(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*commandOptions)
		wants string // substring expected in the error
	}{
		{"empty kmsSocket", func(o *commandOptions) { o.kmsSocket = "" }, "--kms-socket"},
		{"zero probeInterval", func(o *commandOptions) { o.probeInterval = 0 }, "--probe-interval"},
		{"zero probeIntervalUnhealthy", func(o *commandOptions) { o.probeIntervalUnhealthy = 0 }, "--probe-interval-unhealthy"},
		{"zero probeTimeout", func(o *commandOptions) { o.probeTimeout = 0 }, "--probe-timeout"},
		{"zero writeTimeout", func(o *commandOptions) { o.writeTimeout = 0 }, "--write-timeout"},
		{"empty configmapNamespace", func(o *commandOptions) { o.configmapNamespace = "" }, "--configmap-namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := validOpts()
			tc.mut(&o)
			err := o.validate()
			if err == nil {
				t.Fatalf("validate: want error containing %q, got nil", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("validate: got %q, want substring %q", err.Error(), tc.wants)
			}
		})
	}
}

func TestValidate_outputModeEnum(t *testing.T) {
	cases := []struct {
		name       string
		mode       string
		wantErr    bool
		wantSubstr string
	}{
		{"configmap accepted", outputModeConfigMap, false, ""},
		{"condition rejected as reserved", outputModeCondition, true, "reserved for the OpenShift track"},
		{"unknown rejected with both options listed", "bogus", true, `must be "configmap" or "condition"`},
		{"empty rejected with both options listed", "", true, `must be "configmap" or "condition"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := validOpts()
			o.outputMode = tc.mode
			err := o.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate: want error containing %q, got nil", tc.wantSubstr)
				}
				if !strings.Contains(err.Error(), tc.wantSubstr) {
					t.Errorf("validate: got %q, want substring %q", err.Error(), tc.wantSubstr)
				}
				return
			}
			if err != nil {
				t.Errorf("validate: got %v, want nil", err)
			}
		})
	}
}

func TestAddFlags_observerPodNameDefaultsFromPodNameEnv(t *testing.T) {
	t.Setenv("POD_NAME", "from-env-0")
	o := commandOptions{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.addFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if o.observerPodName != "from-env-0" {
		t.Errorf("observerPodName: got %q, want %q (env-derived flag default)", o.observerPodName, "from-env-0")
	}
}

func TestValidate_observerPodNameRequiredWhenEmpty(t *testing.T) {
	o := validOpts()
	o.observerPodName = ""

	err := o.validate()
	if err == nil {
		t.Fatal("validate: want error, got nil")
	}
	if !strings.Contains(err.Error(), "--observer-pod-name") {
		t.Errorf("validate: got %q, want substring --observer-pod-name", err.Error())
	}
}

func TestValidate_configmapNameDefaultsFromObserverPodName(t *testing.T) {
	o := validOpts()
	o.configmapName = "" // force the wrapped default

	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	want := "kms-health-master-0"
	if o.configmapName != want {
		t.Errorf("configmapName: got %q, want %q (wrapped default from observerPodName)", o.configmapName, want)
	}
}

func TestAddFlagsAndValidate_configmapNameDefaultChainsThroughEnv(t *testing.T) {
	// Verifies the full chain (env → observerPodName → configmapName)
	// across the two layers it now spans: addFlags reads $POD_NAME at
	// flag-registration time, validate derives configmapName from the
	// resolved observerPodName.
	t.Setenv("POD_NAME", "kube-apiserver-3")
	// Field defaults that addFlags wires to non-empty values
	// (kmsSocket, probeInterval, etc.) come from this struct literal —
	// addFlags references them as the flag default. Fields that addFlags
	// defaults to "" (configmapNamespace, configmapName, observerPodName)
	// have to be supplied via flag args, since addFlags ignores the
	// struct value for those.
	o := commandOptions{
		kmsSocket:              "/var/run/kms.sock",
		probeInterval:          60 * time.Second,
		probeIntervalUnhealthy: 10 * time.Second,
		probeTimeout:           3 * time.Second,
		writeTimeout:           5 * time.Second,
		outputMode:             outputModeConfigMap,
	}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.addFlags(fs)
	if err := fs.Parse([]string{"--configmap-namespace=kms-health-test"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if o.observerPodName != "kube-apiserver-3" {
		t.Errorf("observerPodName: got %q, want kube-apiserver-3", o.observerPodName)
	}
	if o.configmapName != "kms-health-kube-apiserver-3" {
		t.Errorf("configmapName: got %q, want kms-health-kube-apiserver-3", o.configmapName)
	}
}

func TestValidate_explicitConfigmapNameNotOverridden(t *testing.T) {
	o := validOpts()
	o.configmapName = "explicit-cm"

	if err := o.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if o.configmapName != "explicit-cm" {
		t.Errorf("configmapName: got %q, want explicit-cm (default must not override caller-set value)", o.configmapName)
	}
}
