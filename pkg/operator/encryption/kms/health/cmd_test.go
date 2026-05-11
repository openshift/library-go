package health

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func validOpts() commandOptions {
	return commandOptions{
		kmsSocket:        "/var/run/kms.sock",
		probeInterval:    60 * time.Second,
		probeTimeout:     3 * time.Second,
		writeTimeout:     5 * time.Second,
		operatorResource: "kubeapiserver",
		observerPodName:  "master-0",
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
		wants string
	}{
		{"empty kmsSocket", func(o *commandOptions) { o.kmsSocket = "" }, "--kms-socket"},
		{"zero probeInterval", func(o *commandOptions) { o.probeInterval = 0 }, "--probe-interval"},
		{"zero probeTimeout", func(o *commandOptions) { o.probeTimeout = 0 }, "--probe-timeout"},
		{"zero writeTimeout", func(o *commandOptions) { o.writeTimeout = 0 }, "--write-timeout"},
		{"empty observerPodName", func(o *commandOptions) { o.observerPodName = "" }, "--observer-pod-name"},
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

func TestValidate_operatorResourceEnum(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		wantErr  bool
	}{
		{"kubeapiserver accepted", "kubeapiserver", false},
		{"authentication accepted", "authentication", false},
		{"openshiftapiserver accepted", "openshiftapiserver", false},
		{"unknown rejected", "bogus", true},
		{"empty rejected", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := validOpts()
			o.operatorResource = tc.resource
			err := o.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate(%q): want error, got nil", tc.resource)
				}
				if !strings.Contains(err.Error(), "--operator-resource") {
					t.Errorf("validate(%q): got %q, want substring --operator-resource", tc.resource, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("validate(%q): got %v, want nil", tc.resource, err)
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
