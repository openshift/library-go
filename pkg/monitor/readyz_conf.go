package monitor

// ReadyZConf is used to configure a https readyZ probe, used by the guard controller
type ReadyZConf struct {
	Endpoint                      string
	Port                          string
	InitialDelaySeconds           int32
	TimeoutSeconds                int32
	PeriodSeconds                 int32
	SuccessThreshold              int32
	FailureThreshold              int32
	TerminationGracePeriodSeconds *int64
}

func NewGuardPodDefaultReadyZConfig(endpoint, port string) *ReadyZConf {
	return &ReadyZConf{
		Endpoint:                      endpoint,
		Port:                          port,
		InitialDelaySeconds:           0,
		TimeoutSeconds:                5,
		PeriodSeconds:                 5,
		SuccessThreshold:              1,
		FailureThreshold:              3,
		TerminationGracePeriodSeconds: nil,
	}
}
