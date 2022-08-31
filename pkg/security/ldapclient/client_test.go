package ldapclient

import (
	"testing"

	"golang.org/x/net/proxy"
)

// TestProxyDialerIsContextDialer verifies that proxy.FromEnviroment returns a ContextDialer
func TestProxyDialerIsContextDialer(t *testing.T) {
	dialer := proxy.FromEnvironment()
	if _, ok := dialer.(proxy.ContextDialer); !ok {
		t.Errorf("proxy.FromEnvironment() did not return a ContextDialer")
	}
}
