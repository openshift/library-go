// Command fake-plugin is a disposable KMSv2 plugin for the KIND
// harness: AES-GCM encryption with a hard-coded key (NEVER for
// production use), plus a file-presence toggle that flips Status()
// between "ok" and "unhealthy:test-forced" so verify.sh can exercise
// both branches of the monitor's classification.
//
// Replaces upstream's softhsm-backed mock plugin at the same UDS path.
// ~90 lines of code; stays deliberately small so its disposability is
// obvious from a glance.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	kmsservice "k8s.io/kms/pkg/service"
)

// testKey is the AES-256-GCM key our fake uses to (un)wrap every DEK
// kube-apiserver sends. Fixed so decryption works across restarts of
// the fake; value is meaningless outside this KIND harness.
var testKey = []byte("0123456789abcdef0123456789abcdef")

const fakeKeyID = "kms-health-kind-test-key-v1"

type plugin struct {
	markerPath string
}

func (p *plugin) Status(ctx context.Context) (*kmsservice.StatusResponse, error) {
	healthz := "ok"
	if _, err := os.Stat(p.markerPath); err == nil {
		healthz = "unhealthy:test-forced"
	}
	return &kmsservice.StatusResponse{
		Healthz: healthz,
		Version: "v2",
		KeyID:   fakeKeyID,
	}, nil
}

func (p *plugin) Encrypt(ctx context.Context, uid string, data []byte) (*kmsservice.EncryptResponse, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return &kmsservice.EncryptResponse{
		Ciphertext: gcm.Seal(nonce, nonce, data, nil),
		KeyID:      fakeKeyID,
	}, nil
}

func (p *plugin) Decrypt(ctx context.Context, uid string, req *kmsservice.DecryptRequest) ([]byte, error) {
	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(req.Ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(req.Ciphertext))
	}
	return gcm.Open(nil, req.Ciphertext[:ns], req.Ciphertext[ns:], nil)
}

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(testKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func main() {
	socket := flag.String("socket", "/var/run/kmsplugin-fake/kms.sock", "UDS path to listen on")
	marker := flag.String("unhealthy-marker", "/var/run/kmsplugin-fake/kms-unhealthy", "flipping this file's existence forces Status() to return unhealthy")
	staydown := flag.String("staydown-marker", "/var/run/kmsplugin-fake/kms-staydown", "if this file exists at startup, sleep before listening so verify.sh can observe a real outage window")
	staydownFor := flag.Duration("staydown-duration", 3*time.Second, "how long to sleep when staydown marker is present at startup")
	flag.Parse()

	// Stay-down marker: when verify.sh wants assertion 6 to observe an
	// rpc-error, it sets this file before killing the container. Kubelet
	// restarts us, we see the marker on this fresh start, and sleep
	// before listening so the gap is wide enough for a probe timeout to
	// fire regardless of kubelet's restart speed.
	if _, err := os.Stat(*staydown); err == nil {
		log.Printf("fake-plugin: %s present, sleeping %s before listening", *staydown, *staydownFor)
		time.Sleep(*staydownFor)
	}

	// Idempotent: remove any stale socket from a prior crash. Must do
	// this before ListenAndServe or the bind fails with "address in use".
	_ = os.Remove(*socket)

	svc := &plugin{markerPath: *marker}
	server := kmsservice.NewGRPCService(*socket, 5*time.Second, svc)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()

	log.Printf("fake-plugin: listening on %s (marker=%s)", *socket, *marker)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		log.Print("fake-plugin: signal received, shutting down")
	case err := <-serverErr:
		log.Fatalf("fake-plugin: server exited: %v", err)
	}
	server.Shutdown()
}
