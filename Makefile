.PHONY: build run clean

# Build the application
build:
	go build -o bin/goalie ./cmd/goalie

# Run the application
run:
	go run ./cmd/goalie/main.go

# Run with arguments
# Usage: make runargs ARGS="--provider=google example.com"
runargs:
	go run ./cmd/goalie/main.go $(ARGS)

# Clean build artifacts
clean:
	rm -rf bin/