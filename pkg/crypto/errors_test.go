package crypto

import (
	"crypto/x509"
	"fmt"
	"net"
	"testing"
)

func TestFormatHostnameError(t *testing.T) {
	tests := []struct {
		name     string
		err      x509.HostnameError
		expected string
	}{
		{
			name: "nil certificate",
			err: x509.HostnameError{
				Host:        "example.com",
				Certificate: nil,
			},
			expected: "x509: cannot validate certificate for example.com",
		},
		{
			name: "DNS name mismatch with single SAN",
			err: x509.HostnameError{
				Host: "example.com",
				Certificate: &x509.Certificate{
					DNSNames: []string{"other.com"},
				},
			},
			expected: "x509: certificate is valid for other.com, not example.com",
		},
		{
			name: "DNS name mismatch with multiple SANs",
			err: x509.HostnameError{
				Host: "example.com",
				Certificate: &x509.Certificate{
					DNSNames: []string{"foo.com", "bar.com", "baz.com"},
				},
			},
			expected: "x509: certificate is valid for foo.com, bar.com, baz.com, not example.com",
		},
		{
			name: "DNS name with no SANs",
			err: x509.HostnameError{
				Host: "example.com",
				Certificate: &x509.Certificate{
					DNSNames: []string{},
				},
			},
			expected: "x509: certificate is not valid for any names, but wanted to match example.com",
		},
		{
			name: "IP address mismatch with single IP SAN",
			err: x509.HostnameError{
				Host: "192.168.1.1",
				Certificate: &x509.Certificate{
					IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
				},
			},
			expected: "x509: certificate is valid for 10.0.0.1, not 192.168.1.1",
		},
		{
			name: "IP address mismatch with multiple IP SANs",
			err: x509.HostnameError{
				Host: "192.168.1.1",
				Certificate: &x509.Certificate{
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.1"),
						net.ParseIP("10.0.0.2"),
					},
				},
			},
			expected: "x509: certificate is valid for 10.0.0.1, 10.0.0.2, not 192.168.1.1",
		},
		{
			name: "IP address with no IP SANs",
			err: x509.HostnameError{
				Host: "192.168.1.1",
				Certificate: &x509.Certificate{
					IPAddresses: []net.IP{},
				},
			},
			expected: "x509: cannot validate certificate for 192.168.1.1 because it doesn't contain any IP SANs",
		},
		{
			name: "IPv6 address mismatch",
			err: x509.HostnameError{
				Host: "::1",
				Certificate: &x509.Certificate{
					IPAddresses: []net.IP{net.ParseIP("fe80::1")},
				},
			},
			expected: "x509: certificate is valid for fe80::1, not ::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatHostnameError(tt.err)
			if result != tt.expected {
				t.Errorf("FormatHostnameError() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatHostnameError_LargeNumberOfSANs(t *testing.T) {
	// Test that we handle certificates with >= 100 SANs by showing count instead of listing
	manyDNSNames := make([]string, 100)
	for i := range manyDNSNames {
		manyDNSNames[i] = fmt.Sprintf("host%d.example.com", i)
	}

	manyIPs := make([]net.IP, 100)
	for i := range manyIPs {
		manyIPs[i] = net.ParseIP(fmt.Sprintf("10.0.0.%d", i%256))
	}

	tests := []struct {
		name     string
		err      x509.HostnameError
		expected string
	}{
		{
			name: "many DNS SANs shows count",
			err: x509.HostnameError{
				Host: "notfound.example.com",
				Certificate: &x509.Certificate{
					DNSNames: manyDNSNames,
				},
			},
			expected: "x509: certificate is valid for 100 names, but none matched notfound.example.com",
		},
		{
			name: "many IP SANs shows count",
			err: x509.HostnameError{
				Host: "192.168.1.1",
				Certificate: &x509.Certificate{
					IPAddresses: manyIPs,
				},
			},
			expected: "x509: certificate is valid for 100 IP SANs, but none matched 192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatHostnameError(tt.err)
			if result != tt.expected {
				t.Errorf("FormatHostnameError() = %q, want %q", result, tt.expected)
			}
		})
	}
}
