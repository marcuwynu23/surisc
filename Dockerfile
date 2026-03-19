# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for Go dependencies and HTTPS requests)
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code (assuming main.go is in cmd/surisc/)
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o surisc cmd/surisc/main.go

# Final stage
FROM alpine:latest

# Add ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/surisc .

# The application is an executable that requires arguments, so we use ENTRYPOINT
# You can override arguments when running the container: docker run <image> -u <url>
ENTRYPOINT ["./surisc"]
