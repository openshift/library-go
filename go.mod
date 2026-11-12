module github.com/openshift/library-go

go 1.27.0

require (
	cel.dev/cel-go v0.33.2
	github.com/blang/semver/v4 v4.0.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/distribution/distribution/v3 v3.0.0-20230511163743-f7717b7855ca
	github.com/fvbommel/sortorder v1.1.0
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/gonum/graph v0.0.0-20170401004347-50b27dea7ebb
	github.com/google/gnostic-models v0.7.1
	github.com/google/go-cmp v0.7.0
	github.com/imdario/mergo v0.3.7
	github.com/moby/sys/user v0.4.0
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
	github.com/onsi/gomega v1.44.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/selinux v1.13.0
	github.com/openshift/api v0.0.0-20261109181719-0a8bc04b7618
	github.com/openshift/build-machinery-go v0.0.0-20250530140348-dc5b2804eeee
	github.com/openshift/client-go v0.0.0-20261026144452-41e357d76bc8
	github.com/openshift/osincli v0.0.0-20160924135400-fababb0555f2
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.74.0
	github.com/prometheus/client_golang v1.25.0
	github.com/robfig/cron v1.2.0
	github.com/sirupsen/logrus v1.10.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.12.1
	go.etcd.io/etcd/client/v3 v3.7.3
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	golang.org/x/time v0.16.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260817212433-ac3dfec99bb1
	gopkg.in/evanphx/json-patch.v4 v4.13.0
	gopkg.in/gcfg.v1 v1.2.3
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	k8s.io/api v0.38.0-beta.0
	k8s.io/apiextensions-apiserver v0.38.0-beta.0
	k8s.io/apimachinery v0.38.0-beta.0
	k8s.io/apiserver v0.38.0-beta.0
	k8s.io/client-go v0.38.0-beta.0
	k8s.io/component-base v0.38.0-beta.0
	k8s.io/klog/v2 v2.140.0
	k8s.io/kms v0.38.0-beta.0
	k8s.io/kube-aggregator v0.38.0-beta.0
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3
	sigs.k8s.io/kube-storage-version-migrator v0.0.6-0.20230721195810-5c8923c5ff96
	sigs.k8s.io/yaml v1.6.0
)

require (
	cel.dev/expr v0.25.3 // indirect
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/emicklei/go-restful/v3 v3.14.0 // indirect
	github.com/felixge/fgprof v0.9.4 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v1.0.2 // indirect
	github.com/go-openapi/jsonreference v1.0.2 // indirect
	github.com/go-openapi/swag/conv v0.29.2 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.2 // indirect
	github.com/go-openapi/swag/pools v0.29.2 // indirect
	github.com/go-openapi/swag/typeutils v0.29.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/gonum/blas v0.0.0-20181208220705-f22b278b28ac // indirect
	github.com/gonum/floats v0.0.0-20181209220543-c233463c7e82 // indirect
	github.com/gonum/internal v0.0.0-20181124074243-f884aa714029 // indirect
	github.com/gonum/lapack v0.0.0-20181123203213-e4cdc5a0bff9 // indirect
	github.com/gonum/matrix v0.0.0-20181209220409-c518dec07be9 // indirect
	github.com/google/pprof v0.0.0-20250403155104-27863c87afa6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.1.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pandatix/go-abnf v0.5.5 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.73.1 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/etcd/api/v3 v3.7.3 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.7.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/apiextensions-api v0.38.0-beta.0 // indirect
	k8s.io/kube-openapi v0.0.0-20261014044854-ca3452a79603 // indirect
	k8s.io/streaming v0.38.0-beta.0 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.37.0 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v7 v7.0.1 // indirect
)

replace github.com/openshift/api => github.com/jacobsee/openshift-api v0.0.0-20261112195451-5fdfa11a3b3f

replace github.com/openshift/client-go => github.com/jacobsee/client-go v0.0.0-20261112195824-941f34779958
