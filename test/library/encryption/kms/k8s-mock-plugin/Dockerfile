ARG UPSTREAM_IMAGE=k8s-mock-kms-plugin-upstream

FROM golang:1.25 AS builder
WORKDIR /workspace
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -mod=vendor \
    -o mock-kms-plugin-wrapper \
    ./test/library/encryption/kms/k8s-mock-plugin/wrapper/

FROM ${UPSTREAM_IMAGE}
COPY --from=builder /workspace/mock-kms-plugin-wrapper /usr/local/bin/vault-kube-kms
ENTRYPOINT ["/usr/local/bin/vault-kube-kms"]
