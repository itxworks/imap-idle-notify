# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

############################
# Builder stage
############################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app

# Copy Go modules files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY imap-idle-notify.go ./

# Build a static binary (no cgo) so it runs on distroless/static.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o imap-idle-notify imap-idle-notify.go

# --- Final minimal image ---
# The distroless static base already ships ca-certificates and zoneinfo.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the binary from builder
COPY --from=builder /app/imap-idle-notify /imap-idle-notify

# Use .env to pass env vars
ENV TZ=UTC

# distroless/static:nonroot already runs as uid 65532
USER nonroot:nonroot

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/imap-idle-notify", "-healthcheck"]

# Run the binary
ENTRYPOINT ["/imap-idle-notify"]
