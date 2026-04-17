FROM golang:latest AS builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /workspace
COPY main.go go.mod ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /vault-kube-kms .

# Generate SoftHSM tokens at build time so the image is fully self-contained.
# Use the same base as the runtime stage to guarantee SoftHSM ABI compatibility.
# Token label, pin, and key params must match softhsm-config.json.
FROM quay.io/openshifttest/mock-kms-plugin:latest AS softhsm-keygen
RUN apk add --no-cache opensc
RUN mkdir -p /var/lib/softhsm/tokens && \
    softhsm2-util --init-token --free \
      --label "kms-test" --pin "1234" --so-pin "1234" && \
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
      --keygen --key-type aes:32 \
      --token-label kms-test --label kms-test --pin 1234

FROM quay.io/openshifttest/mock-kms-plugin:latest

COPY softhsm-config.json /etc/softhsm-config.json
COPY --from=softhsm-keygen /var/lib/softhsm/tokens /var/lib/softhsm/tokens
COPY --from=softhsm-keygen /etc/softhsm2.conf /etc/softhsm2.conf

COPY --from=builder /vault-kube-kms /vault-kube-kms
ENTRYPOINT ["/vault-kube-kms"]
