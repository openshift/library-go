package preflight

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	kmsservice "k8s.io/kms/pkg/service"
)

// healthzOK is the value the KMS plugin returns when healthy.
// See https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kms/apis/v2/api.proto#L39
const healthzOK = "ok"

// checker runs the preflight check against a KMS plugin by calling
// Status, Encrypt, and Decrypt on the kmsservice.Service interface.
// this is the same interface the apiserver uses.
type checker struct {
	service        kmsservice.Service
	randReader     io.Reader
	statusTimeout  time.Duration
	statusInterval time.Duration
}

func newChecker(service kmsservice.Service) *checker {
	return &checker{
		service:        service,
		randReader:     rand.Reader,
		statusTimeout:  30 * time.Second,
		statusInterval: 2 * time.Second,
	}
}

func (c *checker) check(ctx context.Context) error {
	if err := c.checkStatus(ctx); err != nil {
		return err
	}
	return c.checkEncryptDecrypt(ctx)
}

// checkStatus polls the KMS plugin status endpoint until it reports healthy.
// The plugin may not be immediately available after startup, so we retry
// before reporting a failure.
func (c *checker) checkStatus(ctx context.Context) error {
	klog.Infof("[1/3] Checking KMS plugin status endpoint (interval %v, timeout %v)", c.statusInterval, c.statusTimeout)
	return wait.PollUntilContextTimeout(ctx, c.statusInterval, c.statusTimeout, true, func(ctx context.Context) (bool, error) {
		start := time.Now()
		resp, err := c.service.Status(ctx)
		elapsed := time.Since(start)
		if err != nil {
			klog.Infof("  not ready: %v, latency=%v", err, elapsed)
			return false, nil
		}
		// we only check healthz here.
		// version and keyID validation is the apiserver's responsibility,
		// the preflight check just confirms the plugin is reachable and healthy.
		if resp.Healthz != healthzOK {
			klog.Infof("  not ready: healthz=%q, latency=%v", resp.Healthz, elapsed)
			return false, nil
		}
		klog.Infof("  Status: healthz=%q, version=%q, keyID=%q, latency=%v", resp.Healthz, resp.Version, resp.KeyID, elapsed)
		return true, nil
	})
}

func (c *checker) checkEncryptDecrypt(ctx context.Context) error {
	klog.Info("[2/3] Checking KMS plugin encrypt endpoint")
	plainText := make([]byte, 32)
	if _, err := io.ReadFull(c.randReader, plainText); err != nil {
		return fmt.Errorf("failed to generate random plaintext: %w", err)
	}
	// unique per run, used for tracing
	uid := fmt.Sprintf("preflight-check-%x", plainText[:4])
	start := time.Now()
	encResp, err := c.service.Encrypt(ctx, uid, plainText)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("encrypt call failed, latency=%v: %w", elapsed, err)
	}
	if bytes.Equal(encResp.Ciphertext, plainText) {
		return fmt.Errorf("encrypt returned plaintext unchanged, expected encrypted data")
	}
	var annotations []string
	for k, v := range encResp.Annotations {
		annotations = append(annotations, fmt.Sprintf("%s=%q", k, v))
	}
	klog.Infof("  Encrypt: keyID=%q, ciphertext=%d bytes, annotations=[%s], latency=%v", encResp.KeyID, len(encResp.Ciphertext), strings.Join(annotations, ", "), elapsed)

	klog.Info("[3/3] Checking KMS plugin decrypt endpoint")
	decryptReq := &kmsservice.DecryptRequest{Ciphertext: encResp.Ciphertext, KeyID: encResp.KeyID, Annotations: encResp.Annotations}
	start = time.Now()
	decrypted, err := c.service.Decrypt(ctx, uid, decryptReq)
	elapsed = time.Since(start)
	if err != nil {
		return fmt.Errorf("decrypt call failed, latency=%v: %w", elapsed, err)
	}
	if !bytes.Equal(decrypted, plainText) {
		return fmt.Errorf("decrypt roundtrip mismatch: got %q, want %q", decrypted, plainText)
	}
	klog.Infof("  Decrypt: plaintext=%d bytes, latency=%v", len(decrypted), elapsed)
	return nil
}
