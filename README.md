# Goalie - DNS Analysis Tool

A Go tool for DNS lookups over HTTPS (DoH) that identifies hosting and service providers based on DNS records.

## Original CLI Usage

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
- TXT

## Vercel Serverless Function

This project has been configured to run as a Vercel serverless function with a simple web interface.

### Deployment

To deploy to Vercel:

1. Make sure you have the Vercel CLI installed:
   ```
   npm install -g vercel
   ```

2. Login to Vercel:
   ```
   vercel login
   ```

3. Deploy the project:
   ```
   vercel
   ```

4. For production deployment:
   ```
   vercel --prod
   ```

### API Usage

Once deployed, you can access the API at:

```
https://your-vercel-app.vercel.app/api?hostname=example.com
```

Query parameters:
- `hostname` (required): The domain to analyze
- `provider` (optional): DNS provider to use (`google` or `cloudflare`). Defaults to `google`

Example request:
```
https://your-vercel-app.vercel.app/api?hostname=example.com&provider=cloudflare
```

### API Response

The API returns a JSON response with the following structure:

```json
{
  "hostname": "example.com",
  "records": [
    {
      "type": "A",
      "data": "93.184.216.34",
      "provider": "IANA"
    },
    {
      "type": "NS",
      "data": "a.iana-servers.net.",
      "provider": "ICANN"
    }
  ],
  "providers": [
    "IANA",
    "ICANN"
  ],
  "query_time": "1.234567s"
}
```

## Local Development

To run the project locally:

1. Clone the repository
2. Run with Vercel dev:
   ```
   vercel dev
   ```

This will start a local development server that mimics the Vercel production environment.

## Building the CLI version

```bash
go build -o goalie cmd/goalie/main.go
```# dnsapi
