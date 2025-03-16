# Goalie Project Guide

## Build Commands
- Build: `make build` or `go build -o bin/dnsapi ./api`
- Run: `make run` or `go run ./api/index.go`
- Run with args: `make runargs ARGS="--provider=google example.com"`
- Clean: `make clean`
- Local dev server: `vercel dev`
- Deploy: `vercel` (dev) or `vercel --prod` (production)

## Code Style Guidelines
- **Formatting**: Standard Go formatting with `gofmt`
- **Naming**: Use camelCase for variables, PascalCase for exported functions/types
- **Error Handling**: Always check errors and provide context
- **Comments**: Document exports with meaningful comments (follow godoc style)
- **Imports**: Group standard library, external packages, and internal packages
- **File Structure**: Group related functionality into packages/modules
- **Types**: Favor explicit typing, clearly define structs and interfaces
- **HTML/CSS/JS**: Keep presentation logic in templates, follow consistent indentation

## Data Management
- DNS providers defined in `api/data/dns_providers.txt`
- IP ownership info stored in `api/data/ip_owners.csv`