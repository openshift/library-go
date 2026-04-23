package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	kmstesting "github.com/openshift/library-go/test/library/encryption/kms"
)

const upstreamBinary = "/usr/local/bin/mock-kms-plugin"

const (
	defaultConfigPath = "/etc/softhsm-config.json"
	defaultTokensDir  = "/var/lib/softhsm/tokens"
)

type options struct {
	listenAddress       string
	vaultAddress        string
	vaultNamespace      string
	transitMount        string
	transitKey          string
	logLevel            string
	approleRoleID       string
	approleSecretIDPath string
}

func main() {
	o := &options{}

	flag.StringVar(&o.listenAddress, "listen-address", "", "Listen address for the KMS plugin (e.g. unix:///var/run/kmsplugin/kms.sock)")
	flag.StringVar(&o.vaultAddress, "vault-address", "", "Vault server address")
	flag.StringVar(&o.vaultNamespace, "vault-namespace", "", "Vault namespace")
	flag.StringVar(&o.transitMount, "transit-mount", "", "Vault transit secret engine mount path")
	flag.StringVar(&o.transitKey, "transit-key", "", "Vault transit key name")
	flag.StringVar(&o.logLevel, "log-level", "", "Log level (optional, valid value: debug-extended)")
	flag.StringVar(&o.approleRoleID, "approle-role-id", "", "Vault AppRole role ID")
	flag.StringVar(&o.approleSecretIDPath, "approle-secret-id-path", "", "Path to file containing Vault AppRole secret ID")
	flag.Parse()

	flag.VisitAll(func(f *flag.Flag) {
		log.Printf("FLAG: --%s=%q", f.Name, f.Value)
	})

	if err := o.validate(); err != nil {
		log.Fatal(err)
	}
	if err := o.run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func (o *options) validate() error {
	if o.listenAddress == "" {
		return fmt.Errorf("--listen-address must be set")
	}
	if o.vaultAddress == "" {
		return fmt.Errorf("--vault-address must be set")
	}
	if o.vaultNamespace == "" {
		return fmt.Errorf("--vault-namespace must be set")
	}
	if o.transitMount == "" {
		return fmt.Errorf("--transit-mount must be set")
	}
	if o.transitKey == "" {
		return fmt.Errorf("--transit-key must be set")
	}
	if o.logLevel != "" && o.logLevel != "debug-extended" {
		return fmt.Errorf("--log-level must be empty or \"debug-extended\", got %q", o.logLevel)
	}
	if o.approleRoleID == "" {
		return fmt.Errorf("--approle-role-id must be set")
	}
	if o.approleSecretIDPath == "" {
		return fmt.Errorf("--approle-secret-id-path must be set")
	}
	return nil
}

func (o *options) run(ctx context.Context) error {
	log.Printf("Initializing SoftHSM")
	if err := initSoftHSM(ctx); err != nil {
		return fmt.Errorf("failed to initialize SoftHSM: %w", err)
	}

	upstreamArgs := []string{
		"-listen-addr=" + o.listenAddress,
		"-config-file-path=" + defaultConfigPath,
	}
	log.Printf("Executing %s %v", upstreamBinary, upstreamArgs)
	argv := append([]string{upstreamBinary}, upstreamArgs...)
	return syscall.Exec(upstreamBinary, argv, os.Environ())
}

func initSoftHSM(ctx context.Context) error {
	raw, err := kmstesting.ReadAsset("k8s_mock_kms_plugin_configmap.yaml")
	if err != nil {
		return fmt.Errorf("failed to read configmap asset: %w", err)
	}
	data := resourceread.ReadConfigMapV1OrDie(raw).Data

	if err := os.WriteFile(defaultConfigPath, []byte(data["softhsm-config.json"]), 0644); err != nil {
		return err
	}
	if err := os.MkdirAll(defaultTokensDir, 0755); err != nil {
		return err
	}

	tokensB64 := data["softhsm-tokens.tar.gz.b64"]
	cmd := exec.CommandContext(ctx, "sh", "-c", "base64 -d | tar xzf -")
	cmd.Dir = defaultTokensDir
	cmd.Stdin = strings.NewReader(strings.Join(strings.Fields(tokensB64), ""))
	return cmd.Run()
}
