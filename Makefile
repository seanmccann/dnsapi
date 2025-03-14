.PHONY: build run clean

# Build the application
build:
	go build -o bin/dnsapi ./cmd/dnsapi

# Run the application
run:
	go run ./cmd/dnsapi/main.go

# Run with arguments
# Usage: make runargs ARGS="--provider=google example.com"
runargs:
	go run ./cmd/dnsapi/main.go $(ARGS)

# Clean build artifacts
clean:
	rm -rf bin/