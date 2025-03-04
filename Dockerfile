FROM golang:1.22.2-alpine AS builder

WORKDIR /app

# Copy the dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o patroni-watcher ./cmd/patroni-watcher

# Use Alpine for a small image
FROM alpine:latest

WORKDIR /app

# Add ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy the compiled application
COPY --from=builder /app/patroni-watcher /app/patroni-watcher

# Create the config directory
RUN mkdir -p /app/config    

# Copy the example configuration file
COPY config/config.yaml /app/config/

# Run the application
ENTRYPOINT ["/app/patroni-watcher"]
CMD ["-config", "/app/config"] 