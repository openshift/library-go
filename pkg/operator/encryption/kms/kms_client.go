package kms

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	kmsv2 "k8s.io/kms/apis/v2"
)

const (
	// defaultTimeout is the default timeout for KMS operations
	defaultTimeout = 30 * time.Second
)

// KMSClient is an interface for interacting with KMS plugins
type KMSClient interface {
	// Status calls the KMS plugin's Status endpoint and returns the response
	Status(ctx context.Context) (*StatusResponse, error)
	// Close closes the connection to the KMS plugin
	Close() error
}

// StatusResponse represents the response from a KMS Status call
type StatusResponse struct {
	Version string
	Healthz string
	KeyID   string
}

// kmsClient implements the KMSClient interface
type kmsClient struct {
	conn      *grpc.ClientConn
	kmsClient kmsv2.KeyManagementServiceClient
	endpoint  string
}

// NewKMSClient creates a new KMS client for the given unix socket endpoint
func NewKMSClient(ctx context.Context, endpoint string) (KMSClient, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("kms endpoint cannot be empty")
	}

	// Create a dialer for the unix socket connection
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return net.DialTimeout("unix", addr, defaultTimeout)
	}

	// Establish gRPC connection with insecure credentials (local unix socket)
	conn, err := grpc.DialContext(
		ctx,
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KMS plugin at %s: %w", endpoint, err)
	}

	return &kmsClient{
		conn:      conn,
		kmsClient: kmsv2.NewKeyManagementServiceClient(conn),
		endpoint:  endpoint,
	}, nil
}

// Status calls the KMS plugin's Status endpoint
func (c *kmsClient) Status(ctx context.Context) (*StatusResponse, error) {
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	// Call the Status endpoint
	resp, err := c.kmsClient.Status(timeoutCtx, &kmsv2.StatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to call KMS Status endpoint at %s: %w", c.endpoint, err)
	}

	return &StatusResponse{
		Version: resp.GetVersion(),
		Healthz: resp.GetHealthz(),
		KeyID:   resp.GetKeyId(),
	}, nil
}

// Close closes the connection to the KMS plugin
func (c *kmsClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
