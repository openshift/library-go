package controller

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/openshift/api/operatorcontrolplane/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/mergepatch"

	"github.com/openshift/library-go/pkg/checkendpoints/trace"
	"github.com/openshift/library-go/pkg/operator/events"
)

func TestManageStatusLogs(t *testing.T) {
	testOpErr := &net.OpError{Op: "connect", Net: "tcp", Err: errors.New("test error")}
	testDNSErr := &net.OpError{Op: "connect", Net: "tcp", Err: &net.DNSError{Err: "test error", Name: "host"}}

	testCases := []struct {
		name     string
		err      error
		trace    *trace.LatencyInfo
		initial  *v1alpha1.PodNetworkConnectivityCheckStatus
		expected *v1alpha1.PodNetworkConnectivityCheckStatus
	}{
		{
			name: "TCPConnect",
			trace: &trace.LatencyInfo{
				ConnectStart: testTime(0),
				Connect:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(),
			expected: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(0),
			),
		},
		{
			name: "DNSResolve",
			trace: &trace.LatencyInfo{
				DNSStart:     testTime(0),
				DNS:          1 * time.Millisecond,
				ConnectStart: testTime(1),
				Connect:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(),
			expected: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(1),
				withDNSResolveEntry(0),
			),
		},
		{
			name: "DNSError",
			err:  testDNSErr,
			trace: &trace.LatencyInfo{
				DNSStart: testTime(0),
				DNS:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(),
			expected: podNetworkConnectivityCheckStatus(
				withDNSErrorEntry(0),
			),
		},
		{
			name: "TCPConnectError",
			err:  testOpErr,
			trace: &trace.LatencyInfo{
				ConnectStart: testTime(0),
				Connect:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(),
			expected: podNetworkConnectivityCheckStatus(
				withTCPConnectErrorEntry(0),
			),
		},
		{
			name: "DNSResolveTCPConnectError",
			err:  testOpErr,
			trace: &trace.LatencyInfo{
				DNSStart:     testTime(0),
				DNS:          1 * time.Millisecond,
				ConnectStart: testTime(1),
				Connect:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(),
			expected: podNetworkConnectivityCheckStatus(
				withTCPConnectErrorEntry(1),
				withDNSResolveEntry(0),
			),
		},
		{
			name: "SuccessSort",
			trace: &trace.LatencyInfo{
				DNSStart:     testTime(3),
				DNS:          1 * time.Millisecond,
				ConnectStart: testTime(4),
				Connect:      1 * time.Millisecond,
			},
			initial: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(2),
				withTCPConnectEntry(1),
				withTCPConnectEntry(0),
			),
			expected: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(4),
				withDNSResolveEntry(3),
				withTCPConnectEntry(2),
				withTCPConnectEntry(1),
				withTCPConnectEntry(0),
			),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.initial
			updateStatusFuncs := manageStatusLogs(&v1alpha1.PodNetworkConnectivityCheck{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-to-target-endpoint",
				},
				Spec: v1alpha1.PodNetworkConnectivityCheckSpec{
					TargetEndpoint: "host:port",
				},
			}, tc.err, tc.trace)
			for _, updateStatusFunc := range updateStatusFuncs {
				updateStatusFunc(status)
			}
			assert.Equal(t, tc.expected, status)
		})
	}
}

func TestManageStatusOutage(t *testing.T) {
	//testOpErr := &net.OpError{Op: "connect", Net: "tcp", Err: errors.New("test error")}
	testCases := []struct {
		name     string
		err      error
		initial  *v1alpha1.PodNetworkConnectivityCheckStatus
		expected []v1alpha1.OutageEntry
	}{
		{
			name:    "NoLogs",
			initial: podNetworkConnectivityCheckStatus(),
		},
		{
			name: "NoLogsStartedOutage",
			initial: podNetworkConnectivityCheckStatus(
				withOutageEntry(0),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(0),
			},
		},
		{
			name: "NoLogsEndedOutage",
			initial: podNetworkConnectivityCheckStatus(
				withOutageEntry(0, withEnd(1)),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(0, withEnd(1)),
			},
		},
		{
			name: "FailureLogNoOutage",
			initial: podNetworkConnectivityCheckStatus(
				withTCPConnectErrorEntry(3),
				withTCPConnectEntry(2),
				withTCPConnectEntry(1),
				withTCPConnectEntry(0),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(3),
			},
		},
		{
			name: "SuccessLogStartedOutage",
			initial: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(4),
				withTCPConnectErrorEntry(3),
				withTCPConnectEntry(2),
				withTCPConnectEntry(1),
				withTCPConnectEntry(0),
				withOutageEntry(3),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(3, withEnd(4)),
			},
		},
		{
			name: "ErrorLogEndedOutage",
			initial: podNetworkConnectivityCheckStatus(
				withTCPConnectErrorEntry(5),
				withTCPConnectEntry(4),
				withTCPConnectEntry(3),
				withTCPConnectEntry(2),
				withOutageEntry(0, withEnd(1)),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(5),
				*outageEntry(0, withEnd(1)),
			},
		},
		{
			name: "SuccessLogEndedOutageStartedOutage",
			initial: podNetworkConnectivityCheckStatus(
				withTCPConnectEntry(6),
				withTCPConnectErrorEntry(5),
				withTCPConnectEntry(4),
				withTCPConnectEntry(3),
				withTCPConnectEntry(2),
				withOutageEntry(5),
				withOutageEntry(0, withEnd(1)),
			),
			expected: []v1alpha1.OutageEntry{
				*outageEntry(5, withEnd(6)),
				*outageEntry(0, withEnd(1)),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.initial
			manageStatusOutage(events.NewInMemoryRecorder(t.Name()))(status)
			assert.Equal(t, tc.expected, status.Outages)
			if t.Failed() {
				t.Log("\n", mergepatch.ToYAMLOrError(tc.expected))
				t.Log("\n", mergepatch.ToYAMLOrError(status))
			}
		})
	}

}

func testTime(sec int) time.Time {
	return time.Date(2000, 1, 1, 0, 0, sec, 0, time.UTC)
}

func podNetworkConnectivityCheckStatus(options ...func(status *v1alpha1.PodNetworkConnectivityCheckStatus)) *v1alpha1.PodNetworkConnectivityCheckStatus {
	result := &v1alpha1.PodNetworkConnectivityCheckStatus{}
	for _, f := range options {
		f(result)
	}
	return result
}

func withTCPConnectErrorEntry(start int, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withFailureEntry(start, v1alpha1.LogEntryReasonTCPConnectError, "target-endpoint: failed to establish a TCP connection to host:port: connect tcp: test error", options...)
}

func withDNSErrorEntry(start int, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withFailureEntry(start, v1alpha1.LogEntryReasonDNSError, "target-endpoint: failure looking up host host: connect tcp: lookup host: test error", options...)
}

func withDNSResolveEntry(start int, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withSuccessEntry(start, v1alpha1.LogEntryReasonDNSResolve, "target-endpoint: resolved host name host successfully", options...)
}

func withTCPConnectEntry(start int, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withSuccessEntry(start, v1alpha1.LogEntryReasonTCPConnect, "target-endpoint: tcp connection to host:port succeeded", options...)
}

func withSuccessEntry(start int, reason, message string, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withLogEntry(true, start, reason, message, options...)
}

func withFailureEntry(start int, reason, message string, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return withLogEntry(false, start, reason, message, options...)
}

func withLatency(latency time.Duration) func(entry *v1alpha1.LogEntry) {
	return func(entry *v1alpha1.LogEntry) {
		entry.Latency = metav1.Duration{Duration: latency}
	}
}

func outageEntry(start int, options ...func(entry *v1alpha1.OutageEntry)) *v1alpha1.OutageEntry {
	result := &v1alpha1.OutageEntry{Start: metav1.NewTime(testTime(start))}
	for _, f := range options {
		f(result)
	}
	return result
}

func withEnd(end int) func(*v1alpha1.OutageEntry) {
	return func(entry *v1alpha1.OutageEntry) {
		entry.End = metav1.NewTime(testTime(end))
	}
}

func withOutageEntry(start int, options ...func(entry *v1alpha1.OutageEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	return func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
		status.Outages = append(status.Outages, *outageEntry(start, options...))
	}
}

func withLogEntry(success bool, start int, reason, message string, options ...func(entry *v1alpha1.LogEntry)) func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
	entry := &v1alpha1.LogEntry{
		Start:   metav1.NewTime(testTime(start)),
		Success: success,
		Reason:  reason,
		Message: message,
		Latency: metav1.Duration{Duration: 1 * time.Millisecond},
	}
	for _, f := range options {
		f(entry)
	}
	if success {
		return func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
			status.Successes = append(status.Successes, *entry)
		}
	}
	return func(status *v1alpha1.PodNetworkConnectivityCheckStatus) {
		status.Failures = append(status.Failures, *entry)
	}
}
