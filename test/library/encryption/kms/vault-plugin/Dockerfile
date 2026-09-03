# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git for go mod download
RUN apk add --no-cache git ca-certificates

# Copy source files
COPY go.mod main.go ./

# Download dependencies and generate go.sum
RUN go mod tidy

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /vault-kms-plugin .

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /vault-kms-plugin /usr/local/bin/vault-kms-plugin

# Create socket directory
RUN mkdir -p /var/run/kmsplugin

ENTRYPOINT ["/usr/local/bin/vault-kms-plugin"]
CMD ["-listen-addr=unix:///var/run/kmsplugin/kms.sock"]
