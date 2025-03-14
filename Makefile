.PHONY: build run clean

# Build the application
build:
	go build -o bin/dnsapi ./api

# Run the application
run:
	go run ./api/index.go

# Run with arguments
# Usage: make runargs ARGS="--provider=google example.com"
runargs:
	go run ./api/index.go $(ARGS)

# Clean build artifacts
clean:
	rm -rf bin/