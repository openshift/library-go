// Vault KMS v2 Plugin for Kubernetes
// This plugin implements the KMS v2 gRPC interface and uses HashiCorp Vault Transit engine
// for encryption/decryption operations.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	kmsapi "k8s.io/kms/apis/v2"
)

const (
	apiVersion = "v2"
	pluginName = "vault-kms-plugin"
)

// Config holds the Vault KMS plugin configuration
type Config struct {
	VaultAddress   string `json:"vaultAddress"`
	TransitKeyName string `json:"transitKeyName"`
	AuthMethod     string `json:"authMethod"`
	RoleIDFile     string `json:"roleIdFile"`
	SecretIDFile   string `json:"secretIdFile"`
	Token          string `json:"token"`
	TLSSkipVerify  bool   `json:"tlsSkipVerify"`
}

// VaultKMSPlugin implements the KMS v2 plugin interface
type VaultKMSPlugin struct {
	kmsapi.UnimplementedKeyManagementServiceServer
	config     Config
	httpClient *http.Client
	token      string
}

func main() {
	listenAddr := flag.String("listen-addr", "unix:///var/run/kmsplugin/kms.sock", "gRPC listen address")
	configFile := flag.String("config-file", "/etc/vault-config/vault-config.json", "Path to config file")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Create plugin
	plugin, err := NewVaultKMSPlugin(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create plugin: %v\n", err)
		os.Exit(1)
	}

	// Parse listen address
	network, address := parseListenAddr(*listenAddr)

	// Remove existing socket if it exists
	if network == "unix" {
		os.Remove(address)
	}

	// Create listener
	listener, err := net.Listen(network, address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on %s: %v\n", *listenAddr, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("Vault KMS plugin listening on %s\n", *listenAddr)
	fmt.Printf("Vault address: %s\n", config.VaultAddress)
	fmt.Printf("Transit key: %s\n", config.TransitKeyName)

	// Create gRPC server
	server := grpc.NewServer()
	kmsapi.RegisterKeyManagementServiceServer(server, plugin)

	// Handle shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		fmt.Println("Shutting down...")
		server.GracefulStop()
	}()

	// Serve
	if err := server.Serve(listener); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to serve: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (Config, error) {
	var config Config

	// Try to load from file
	data, err := os.ReadFile(path)
	if err != nil {
		// Fall back to environment variables
		config.VaultAddress = os.Getenv("VAULT_ADDR")
		config.TransitKeyName = os.Getenv("VAULT_TRANSIT_KEY")
		if config.TransitKeyName == "" {
			config.TransitKeyName = "kubernetes-encryption"
		}
		config.AuthMethod = "approle"
		config.RoleIDFile = "/etc/vault-credentials/role-id"
		config.SecretIDFile = "/etc/vault-credentials/secret-id"
		config.TLSSkipVerify = true

		if config.VaultAddress == "" {
			return config, fmt.Errorf("VAULT_ADDR not set and config file not found: %v", err)
		}
		return config, nil
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config: %v", err)
	}

	return config, nil
}

func parseListenAddr(addr string) (network, address string) {
	if strings.HasPrefix(addr, "unix://") {
		return "unix", strings.TrimPrefix(addr, "unix://")
	}
	return "tcp", addr
}

// NewVaultKMSPlugin creates a new Vault KMS plugin
func NewVaultKMSPlugin(config Config) (*VaultKMSPlugin, error) {
	plugin := &VaultKMSPlugin{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Authenticate with Vault
	if err := plugin.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Vault: %v", err)
	}

	return plugin, nil
}

func (p *VaultKMSPlugin) authenticate() error {
	switch p.config.AuthMethod {
	case "approle":
		return p.authenticateAppRole()
	case "token":
		p.token = p.config.Token
		return nil
	default:
		// Try to read token from environment
		p.token = os.Getenv("VAULT_TOKEN")
		if p.token == "" {
			return p.authenticateAppRole()
		}
		return nil
	}
}

func (p *VaultKMSPlugin) authenticateAppRole() error {
	roleID, err := os.ReadFile(p.config.RoleIDFile)
	if err != nil {
		return fmt.Errorf("failed to read role ID: %v", err)
	}

	secretID, err := os.ReadFile(p.config.SecretIDFile)
	if err != nil {
		return fmt.Errorf("failed to read secret ID: %v", err)
	}

	// Login with AppRole
	loginData := map[string]string{
		"role_id":   strings.TrimSpace(string(roleID)),
		"secret_id": strings.TrimSpace(string(secretID)),
	}

	jsonData, _ := json.Marshal(loginData)
	url := fmt.Sprintf("%s/v1/auth/approle/login", p.config.VaultAddress)

	resp, err := p.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode login response: %v", err)
	}

	p.token = result.Auth.ClientToken
	fmt.Println("Successfully authenticated with Vault using AppRole")
	return nil
}

// Status returns the status of the KMS plugin
func (p *VaultKMSPlugin) Status(ctx context.Context, req *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
	// Check Vault health
	url := fmt.Sprintf("%s/v1/sys/health", p.config.VaultAddress)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return &kmsapi.StatusResponse{
			Version: apiVersion,
			Healthz: "error",
			KeyId:   p.config.TransitKeyName,
		}, nil
	}
	defer resp.Body.Close()

	healthz := "ok"
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusTooManyRequests {
		healthz = "error"
	}

	return &kmsapi.StatusResponse{
		Version: apiVersion,
		Healthz: healthz,
		KeyId:   p.config.TransitKeyName,
	}, nil
}

// Encrypt encrypts the plaintext using Vault Transit engine
func (p *VaultKMSPlugin) Encrypt(ctx context.Context, req *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	// Base64 encode the plaintext
	b64Plaintext := base64.StdEncoding.EncodeToString(req.Plaintext)

	// Call Vault Transit encrypt
	encryptData := map[string]string{
		"plaintext": b64Plaintext,
	}

	jsonData, _ := json.Marshal(encryptData)
	url := fmt.Sprintf("%s/v1/transit/encrypt/%s", p.config.VaultAddress, p.config.TransitKeyName)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("X-Vault-Token", p.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("encrypt failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode encrypt response: %v", err)
	}

	return &kmsapi.EncryptResponse{
		KeyId:      fmt.Sprintf("%s:v%d", p.config.TransitKeyName, result.Data.KeyVersion),
		Ciphertext: []byte(result.Data.Ciphertext),
		Annotations: map[string][]byte{
			"vault.hashicorp.com/transit-key": []byte(p.config.TransitKeyName),
		},
	}, nil
}

// Decrypt decrypts the ciphertext using Vault Transit engine
func (p *VaultKMSPlugin) Decrypt(ctx context.Context, req *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	// Call Vault Transit decrypt
	decryptData := map[string]string{
		"ciphertext": string(req.Ciphertext),
	}

	jsonData, _ := json.Marshal(decryptData)
	url := fmt.Sprintf("%s/v1/transit/decrypt/%s", p.config.VaultAddress, p.config.TransitKeyName)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("X-Vault-Token", p.token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("decrypt failed: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode decrypt response: %v", err)
	}

	// Base64 decode the plaintext
	plaintext, err := base64.StdEncoding.DecodeString(result.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %v", err)
	}

	return &kmsapi.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}
