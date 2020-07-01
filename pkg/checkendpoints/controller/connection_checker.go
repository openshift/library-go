package controller

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	operatorcontrolplanev1alpha1 "github.com/openshift/api/operatorcontrolplane/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/checkendpoints/trace"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operatorcontrolplane/podnetworkconnectivitycheck/v1alpha1helpers"
)

// ConnectionChecker checks a single connection and updates status when appropriate
type ConnectionChecker interface {
	Run(ctx context.Context)
	Stop()
}

// NewConnectionChecker returns a ConnectionChecker.
func NewConnectionChecker(check *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, client v1alpha1helpers.PodNetworkConnectivityCheckClient, recorder events.Recorder) ConnectionChecker {
	return &connectionChecker{
		check:    check,
		client:   client,
		recorder: recorder,
		stop:     make(chan interface{}),
	}
}

type connectionChecker struct {
	check       *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck
	client      v1alpha1helpers.PodNetworkConnectivityCheckClient
	recorder    events.Recorder
	updatesLock sync.Mutex
	updates     []v1alpha1helpers.UpdateStatusFunc
	stop        chan interface{}
}

// add queues status updates in a queue.
func (c *connectionChecker) add(updates ...v1alpha1helpers.UpdateStatusFunc) {
	c.updatesLock.Lock()
	defer c.updatesLock.Unlock()
	c.updates = append(c.updates, updates...)
}

// checkConnection checks the connection every second, updating status as needed
func (c *connectionChecker) checkConnection(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer klog.V(1).Infof("Stopped connectivity check %s.", c.check.Name)
	for {
		select {
		case <-c.stop:
			return
		case <-ctx.Done():
			return

		case <-ticker.C:
			go func() {
				c.checkEndpoint(ctx, c.check)
				c.updateStatus(ctx)
			}()
		}
	}
}

// Run starts the connection checker.
func (c *connectionChecker) Run(ctx context.Context) {
	ctx2, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx2.Done():
		}
	}()
	go wait.UntilWithContext(ctx2, func(ctx context.Context) {
		c.checkConnection(ctx2)
	}, 1*time.Second)
	klog.V(1).Infof("Started connectivity check %s.", c.check.Name)
	<-ctx2.Done()
}

// Stop
func (c *connectionChecker) Stop() {
	close(c.stop)
}

// updateStatus applies updates. If an error occurs applying an update,
// it remain on the queue and retried on the next call to updateStatus.
func (c *connectionChecker) updateStatus(ctx context.Context) {
	c.updatesLock.Lock()
	defer c.updatesLock.Unlock()
	if len(c.updates) > 20 {
		_, _, err := v1alpha1helpers.UpdateStatus(ctx, c.client, c.check.Name, c.updates...)
		if err != nil {
			klog.Warningf("Unable to update %s: %v", c.check.Name, err)
			return
		}
		c.updates = nil
	}
}

// checkEndpoint performs the check and manages the PodNetworkConnectivityCheck.Status changes that result.
func (c *connectionChecker) checkEndpoint(ctx context.Context, check *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck) {
	latencyInfo, err := getTCPConnectLatency(ctx, check.Spec.TargetEndpoint)
	statusUpdates := manageStatusLogs(check, err, latencyInfo)
	if len(statusUpdates) > 0 {
		statusUpdates = append(statusUpdates, manageStatusOutage(c.recorder))
	}
	if len(statusUpdates) > 0 {
		statusUpdates = append(statusUpdates, manageStatusConditions)
	}
	c.add(statusUpdates...)
}

// getTCPConnectLatency connects to a tcp endpoint and collects latency info
func getTCPConnectLatency(ctx context.Context, address string) (*trace.LatencyInfo, error) {
	klog.V(4).Infof("Check BEGIN: %v", address)
	defer klog.V(4).Infof("Check END  : %v", address)
	ctx, latencyInfo := trace.WithLatencyInfoCapture(ctx)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		conn.Close()
	}
	updateMetrics(address, latencyInfo, err)
	return latencyInfo, err
}

// isDNSError returns true if the cause of the net operation error is a DNS error
func isDNSError(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		if _, ok := opErr.Err.(*net.DNSError); ok {
			return true
		}
	}
	return false
}

// manageStatusLogs returns a status update function that updates the PodNetworkConnectivityCheck.Status's
// Successes/Failures logs reflect the results of the check.
func manageStatusLogs(check *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheck, checkErr error, latency *trace.LatencyInfo) []v1alpha1helpers.UpdateStatusFunc {
	var statusUpdates []v1alpha1helpers.UpdateStatusFunc
	description := regexp.MustCompile(".*-to-").ReplaceAllString(check.Name, "")
	host, _, _ := net.SplitHostPort(check.Spec.TargetEndpoint)
	if isDNSError(checkErr) {
		klog.V(2).Infof("%7s | %-15s | %10s | Failure looking up host %s: %v", "Failure", "DNSError", latency.DNS, host, checkErr)
		return append(statusUpdates, v1alpha1helpers.AddFailureLogEntry(operatorcontrolplanev1alpha1.LogEntry{
			Start:   metav1.NewTime(latency.DNSStart),
			Success: false,
			Reason:  operatorcontrolplanev1alpha1.LogEntryReasonDNSError,
			Message: fmt.Sprintf("%s: failure looking up host %s: %v", description, host, checkErr),
			Latency: metav1.Duration{Duration: latency.DNS},
		}))
	}
	if latency.DNS != 0 {
		klog.V(2).Infof("%7s | %-15s | %10s | Resolved host name %s successfully", "Success", "DNSResolve", latency.DNS, host)
		statusUpdates = append(statusUpdates, v1alpha1helpers.AddSuccessLogEntry(operatorcontrolplanev1alpha1.LogEntry{
			Start:   metav1.NewTime(latency.DNSStart),
			Success: true,
			Reason:  operatorcontrolplanev1alpha1.LogEntryReasonDNSResolve,
			Message: fmt.Sprintf("%s: resolved host name %s successfully", description, host),
			Latency: metav1.Duration{Duration: latency.DNS},
		}))
	}
	if checkErr != nil {
		klog.V(2).Infof("%7s | %-15s | %10s | Failed to establish a TCP connection to %s: %v", "Failure", "TCPConnectError", latency.Connect, check.Spec.TargetEndpoint, checkErr)
		return append(statusUpdates, v1alpha1helpers.AddFailureLogEntry(operatorcontrolplanev1alpha1.LogEntry{
			Start:   metav1.NewTime(latency.ConnectStart),
			Success: false,
			Reason:  operatorcontrolplanev1alpha1.LogEntryReasonTCPConnectError,
			Message: fmt.Sprintf("%s: failed to establish a TCP connection to %s: %v", description, check.Spec.TargetEndpoint, checkErr),
			Latency: metav1.Duration{Duration: latency.Connect},
		}))
	}
	klog.V(2).Infof("%7s | %-15s | %10s | TCP connection to %v succeeded", "Success", "TCPConnect", latency.Connect, check.Spec.TargetEndpoint)
	return append(statusUpdates, v1alpha1helpers.AddSuccessLogEntry(operatorcontrolplanev1alpha1.LogEntry{
		Start:   metav1.NewTime(latency.ConnectStart),
		Success: true,
		Reason:  operatorcontrolplanev1alpha1.LogEntryReasonTCPConnect,
		Message: fmt.Sprintf("%s: tcp connection to %s succeeded", description, check.Spec.TargetEndpoint),
		Latency: metav1.Duration{Duration: latency.Connect},
	}))
}

// manageStatusOutage returns a status update function that manages the
// PodNetworkConnectivityCheck.Status entries based on Successes/Failures log entries.
func manageStatusOutage(recorder events.Recorder) v1alpha1helpers.UpdateStatusFunc {
	return func(status *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheckStatus) {
		// This func is kept simple by assuming that only on log entry has been
		// added since the last time this method was invoked. See checkEndpoint func.
		var currentOutage *operatorcontrolplanev1alpha1.OutageEntry
		if len(status.Outages) > 0 && status.Outages[0].End.IsZero() {
			currentOutage = &status.Outages[0]
		}
		var latestFailure, latestSuccess operatorcontrolplanev1alpha1.LogEntry
		if len(status.Failures) > 0 {
			latestFailure = status.Failures[0]
		}
		if len(status.Successes) > 0 {
			latestSuccess = status.Successes[0]
		}
		if currentOutage == nil {
			if latestFailure.Start.After(latestSuccess.Start.Time) {
				recorder.Warningf("ConnectivityOutageDetected", "Connectivity outage detected: %s", latestFailure.Message)
				status.Outages = append([]operatorcontrolplanev1alpha1.OutageEntry{{Start: latestFailure.Start}}, status.Outages...)
			}
		} else {
			if latestSuccess.Start.After(latestFailure.Start.Time) {
				recorder.Eventf("ConnectivityRestored", "Connectivity restored: %s", latestSuccess.Message)
				currentOutage.End = latestSuccess.Start
			}
		}
	}
}

// manageStatusConditions returns a status update function that set the appropriate conditions on the
// PodNetworkConnectivityCheck.
func manageStatusConditions(status *operatorcontrolplanev1alpha1.PodNetworkConnectivityCheckStatus) {
	reachableCondition := operatorcontrolplanev1alpha1.PodNetworkConnectivityCheckCondition{
		Type:   operatorcontrolplanev1alpha1.Reachable,
		Status: metav1.ConditionUnknown,
	}
	if len(status.Outages) == 0 || !status.Outages[0].End.IsZero() {
		var latestSuccessLogEntry operatorcontrolplanev1alpha1.LogEntry
		if len(status.Successes) > 0 {
			latestSuccessLogEntry = status.Successes[0]
		}
		reachableCondition.Status = metav1.ConditionTrue
		reachableCondition.Reason = "TCPConnectSuccess"
		reachableCondition.Message = latestSuccessLogEntry.Message
	} else {
		var latestFailureLogEntry operatorcontrolplanev1alpha1.LogEntry
		if len(status.Failures) > 0 {
			latestFailureLogEntry = status.Failures[0]
		}
		reachableCondition.Status = metav1.ConditionFalse
		reachableCondition.Reason = latestFailureLogEntry.Reason
		reachableCondition.Message = latestFailureLogEntry.Message
	}
	v1alpha1helpers.SetPodNetworkConnectivityCheckCondition(&status.Conditions, reachableCondition)
}
