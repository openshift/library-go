package healthmonitor

import "time"

// WithUnHealthyProbesThreshold specifies consecutive failed health checks after which a target is considered unhealthy
func (sm *HealthMonitor) WithUnHealthyProbesThreshold(unhealthyProbesThreshold int) *HealthMonitor {
	sm.unhealthyProbesThreshold = unhealthyProbesThreshold
	return sm
}

// WithHealthyProbesThreshold  specifies consecutive successful health checks after which a target is considered healthy
func (sm *HealthMonitor) WithHealthyProbesThreshold(healthyProbesThreshold int) *HealthMonitor {
	sm.healthyProbesThreshold = healthyProbesThreshold
	return sm
}

// WithProbeResponseTimeout specifies a time limit for requests made by the HTTP client for the health check
func (sm *HealthMonitor) WithProbeResponseTimeout(probeResponseTimeout time.Duration) *HealthMonitor {
	sm.client.Timeout = probeResponseTimeout
	return sm
}

// WithProbeInterval specifies a time interval at which health checks are send
func (sm *HealthMonitor) WithProbeInterval(probeInterval time.Duration) *HealthMonitor {
	sm.probeInterval = probeInterval
	return sm
}

// WithMetrics specifies a set of methods that are used to register various metrics
func (sm *HealthMonitor) WithMetrics(metrics *Metrics) *HealthMonitor {
	sm.metrics = metrics
	return sm
}
