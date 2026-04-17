// vault-kube-kms wrapper: accepts all HashiCorp vault-kube-kms flags,
// translates them, and exec's the upstream Kubernetes mock KMS plugin.
//
// This lets the OpenShift encryption operator use this image as a
// drop-in VaultImage without needing a Vault Enterprise license.
// The upstream mock handles encryption via SoftHSM/PKCS#11.
//
// The SoftHSM config and pre-generated tokens are baked into the
// container image so no init container or external ConfigMap is needed.
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
)

const (
	upstreamBinary = "/usr/local/bin/mock-kms-plugin"

	// Baked into the image at build time; not user-configurable.
	softhsmConfigFile = "/etc/softhsm-config.json"
)

func main() {
	listenAddr := flag.String("listen-address", "unix:///var/run/kmsplugin/kms.sock", "gRPC listen address")
	timeout := flag.Duration("timeout", 0, "gRPC timeout (passed through)")

	// All flags below match the HashiCorp vault-kube-kms binary exactly.
	// They are accepted by this wrapper and silently dropped before exec.
	_ = flag.String("vault-address", "", "(ignored) Vault server address")
	_ = flag.String("vault-namespace", "", "(ignored) Vault namespace")
	_ = flag.String("vault-connection-timeout", "10s", "(ignored) Vault connection timeout")
	_ = flag.String("transit-mount", "transit", "(ignored) Vault transit mount path")
	_ = flag.String("transit-key", "kms-key", "(ignored) Vault transit key name")
	_ = flag.String("auth-method", "approle", "(ignored) Vault auth method")
	_ = flag.String("auth-mount", "approle", "(ignored) Vault auth mount path")
	_ = flag.String("approle-role-id", "", "(ignored) Vault AppRole role ID")
	_ = flag.String("approle-secret-id-path", "", "(ignored) Path to Vault AppRole secret ID file")
	_ = flag.String("tls-ca-file", "", "(ignored) Path to Vault CA certificate")
	_ = flag.String("tls-sni", "", "(ignored) Vault TLS server name indicator")
	_ = flag.Bool("tls-skip-verify", false, "(ignored) Skip TLS verification")
	_ = flag.String("log-level", "info", "(ignored) Log level")
	_ = flag.String("metrics-port", "8080", "(ignored) Metrics/health port")
	_ = flag.Bool("disable-runtime-metrics", false, "(ignored) Disable Go runtime metrics")
	flag.Parse()

	args := []string{
		upstreamBinary,
		fmt.Sprintf("-listen-addr=%s", *listenAddr),
		fmt.Sprintf("-config-file-path=%s", softhsmConfigFile),
	}
	if *timeout > 0 {
		args = append(args, fmt.Sprintf("-timeout=%s", *timeout))
	}

	fmt.Println("vault-kube-kms wrapper: translating Vault flags → upstream mock")
	fmt.Printf("vault-kube-kms wrapper: exec %s %v\n", upstreamBinary, args[1:])

	if err := syscall.Exec(upstreamBinary, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "vault-kube-kms wrapper: exec failed: %v\n", err)
		os.Exit(1)
	}
}
