# Goalie

A Go tool for DNS lookups over HTTPS (DoH).

## Usage

```bash
# Basic usage (defaults to Cloudflare DoH)
go run cmd/goalie/main.go example.com

# Use Google DoH instead
go run cmd/goalie/main.go --provider=google example.com
```

The tool will query the following DNS record types:
- A
- AAAA
- MX
- NS

## Building

```bash
go build -o goalie cmd/goalie/main.go
```