# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23
ARG ALPINE_VERSION=3.22.1

############################
# Builder stage
############################
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app

# Install git for go modules (if needed)
RUN apk add --no-cache ca-certificates tzdata git


# Copy Go modules files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY imap-idle-notify.go ./

# Build the binary
RUN go build -o imap-idle-notify imap-idle-notify.go

# --- Final minimal image ---
FROM alpine:${ALPINE_VERSION}

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/imap-idle-notify ./

# Copy certificates if needed (optional)
# COPY certs/ /app/certs/

# Use .env to pass env vars
ENV TZ=UTC

# Run the binary
CMD ["./imap-idle-notify"]
