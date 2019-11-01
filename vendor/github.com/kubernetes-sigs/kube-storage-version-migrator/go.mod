module github.com/kubernetes-sigs/kube-storage-version-migrator

go 1.12

require (
	github.com/beorn7/perks v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20191002201903-404acd9df4cc // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/openshift/library-go v0.0.0-20190923093227-76b67dd70a86
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90
	github.com/prometheus/common v0.3.0 // indirect
	github.com/prometheus/procfs v0.0.0-20190503130316-740c07785007 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-kubernetes-1.16.2
	k8s.io/apiextensions-apiserver v0.0.0-kubernetes-1.16.2
	k8s.io/apimachinery v0.0.0-kubernetes-1.16.2
	k8s.io/client-go v0.0.0-kubernetes-1.16.2
	k8s.io/klog v0.4.0
	k8s.io/kube-aggregator v0.0.0-kubernetes-1.16.2
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110408-35e52d86657a
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113550-5357c4baaf65
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115801-a2eda9f80ab8
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016111102-bec269661e48
	k8s.io/klog => k8s.io/klog v0.1.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191016112429-9587704a8ad4
)
