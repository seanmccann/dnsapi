package api

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed data/ip_owners.csv data/dns_providers.txt
var embeddedData embed.FS

//go:embed templates/index.html
var templateFS embed.FS

const (
	cloudflareDoH = "https://cloudflare-dns.com/dns-query"
	googleDoH     = "https://dns.google/dns-query"
)

type DNSResponse struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer,omitempty"`
}

type QueryResult struct {
	RecordName string
	Response   *DNSResponse
	Error      error
}

type IPBlock struct {
	CIDR  string
	Owner string
}

// DNSProvider holds information about DNS service providers
type DNSProvider struct {
	Type    string // MX, NS, or TXT
	Pattern string
	Name    string
}

// loadEmbeddedIPOwners loads IP block ownership information from the embedded CSV data
func loadEmbeddedIPOwners() ([]IPBlock, error) {
	file, err := embeddedData.Open("data/ip_owners.csv")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Skip header
	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	var ipBlocks []IPBlock
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) >= 2 {
			ipBlocks = append(ipBlocks, IPBlock{
				CIDR:  record[0],
				Owner: record[1],
			})
		}
	}

	return ipBlocks, nil
}

// loadDNSProviders loads DNS provider information from the embedded text file
func loadDNSProviders() ([]DNSProvider, error) {
	file, err := embeddedData.Open("data/dns_providers.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := csv.NewReader(file)
	scanner.Comma = ','
	scanner.FieldsPerRecord = 3

	var providers []DNSProvider
	for {
		record, err := scanner.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) == 3 {
			providers = append(providers, DNSProvider{
				Type:    record[0],
				Pattern: record[1],
				Name:    record[2],
			})
		}
	}

	return providers, nil
}

// identifyDNSProvider identifies the provider based on domain pattern matching for a specific record type
func identifyDNSProvider(data string, recordType string, providers []DNSProvider) string {
	lowerData := strings.ToLower(data)

	for _, provider := range providers {
		if provider.Type == recordType {
			if recordType == "TXT" && strings.HasPrefix(lowerData, strings.ToLower(provider.Pattern)) {
				return provider.Name
			} else if strings.Contains(lowerData, provider.Pattern) {
				return provider.Name
			}
		}
	}

	return ""
}

// findIPOwner finds the owner of an IP address by checking if it falls within any known IP blocks
func findIPOwner(ip string, blocks []IPBlock) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "Unknown"
	}

	for _, block := range blocks {
		_, ipNet, err := net.ParseCIDR(block.CIDR)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return block.Owner
		}
	}

	return "Unknown"
}

// JSONOutput represents the structure of the JSON response
type JSONOutput struct {
	Hostname  string         `json:"hostname"`
	Records   []RecordOutput `json:"records"`
	Providers []string       `json:"providers"`
	QueryTime string         `json:"query_time"`
}

// RecordOutput represents a single DNS record in the output
type RecordOutput struct {
	Type     string `json:"type"`
	Data     string `json:"data"`
	Provider string `json:"provider,omitempty"`
}

// PageData represents the data passed to the HTML template
type PageData struct {
	Hostname string
	Data     *JSONOutput
}

// Handler function for Vercel serverless function
func Handler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Set CORS headers to allow all origins
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only accept GET requests
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	hostname := r.URL.Query().Get("hostname")

	// Check the path to see if this is an API request or a page request
	if r.URL.Path == "/api" {
		// This is an API request - return JSON data
		if hostname == "" {
			http.Error(w, "Missing hostname parameter", http.StatusBadRequest)
			return
		}

		handleAPIRequest(w, hostname, startTime)
		return
	}

	// Check if this is a request for a specific hostname page
	var hostnameFromPath string
	if strings.HasPrefix(r.URL.Path, "/hosts/") {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 3 {
			hostnameFromPath = parts[2]
			hostname = hostnameFromPath
		}
	}

	// Load the HTML template
	tmpl, err := template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading template: %v", err), http.StatusInternalServerError)
		return
	}

	var data *JSONOutput
	if hostname != "" {
		// Get the DNS data for server-side rendering
		data = fetchDNSData(hostname, startTime)
	}

	// Set content type header
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Render the template with the data
	pageData := PageData{
		Hostname: hostname,
		Data:     data,
	}

	if err := tmpl.Execute(w, pageData); err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
	}
}

// Handles API requests and returns JSON
func handleAPIRequest(w http.ResponseWriter, hostname string, startTime time.Time) {
	output := fetchDNSData(hostname, startTime)

	// Set content type header
	w.Header().Set("Content-Type", "application/json")

	// Output the JSON
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
	}
}

// Fetches DNS data for a hostname
func fetchDNSData(hostname string, startTime time.Time) *JSONOutput {
	// Load IP ownership information from embedded data
	ipBlocks, err := loadEmbeddedIPOwners()
	if err != nil {
		// Log the error but continue with empty blocks
		ipBlocks = []IPBlock{}
	}

	// Load DNS provider information from embedded data
	dnsProviders, err := loadDNSProviders()
	if err != nil {
		// Log the error but continue with empty providers
		dnsProviders = []DNSProvider{}
	}

	// Always use Google DNS
	dohURL := googleDoH

	recordTypes := map[string]int{
		"A":    1,
		"AAAA": 28,
		"MX":   15,
		"NS":   2,
		"TXT":  16,
	}

	var wg sync.WaitGroup
	results := make(chan QueryResult, len(recordTypes))

	// Launch concurrent queries
	for recordName, recordType := range recordTypes {
		wg.Add(1)
		go func(name string, rtype int) {
			defer wg.Done()
			resp, err := queryDoH(dohURL, hostname, rtype)
			results <- QueryResult{
				RecordName: name,
				Response:   resp,
				Error:      err,
			}
		}(recordName, recordType)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Create the JSON output structure
	output := &JSONOutput{
		Hostname:  hostname,
		Records:   []RecordOutput{},
		Providers: []string{},
	}

	// Track unique providers
	uniqueProviders := make(map[string]bool)

	// Process results as they arrive
	for result := range results {
		if result.Error != nil {
			continue
		}

		if len(result.Response.Answer) == 0 {
			continue
		}

		for _, answer := range result.Response.Answer {
			var provider string
			// For A records (IPv4) and AAAA records (IPv6), try to determine the owner
			if (result.RecordName == "A" || result.RecordName == "AAAA") && len(ipBlocks) > 0 {
				owner := findIPOwner(answer.Data, ipBlocks)
				if owner != "Unknown" {
					provider = owner
					uniqueProviders[owner] = true
				}
			} else if (result.RecordName == "MX" || result.RecordName == "NS" || result.RecordName == "TXT") && len(dnsProviders) > 0 {
				providerName := identifyDNSProvider(answer.Data, result.RecordName, dnsProviders)
				if providerName != "" {
					provider = providerName
					uniqueProviders[providerName] = true
				}
			}

			// Add to JSON output
			output.Records = append(output.Records, RecordOutput{
				Type:     result.RecordName,
				Data:     answer.Data,
				Provider: provider,
			})
		}
	}

	elapsed := time.Since(startTime)

	// Add providers to the output
	for provider := range uniqueProviders {
		output.Providers = append(output.Providers, provider)
	}
	output.QueryTime = elapsed.String()

	return output
}

func queryDoH(dohURL, hostname string, recordType int) (*DNSResponse, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	params := url.Values{}

	// For Google DNS, use '/resolve' endpoint for the JSON API
	if strings.Contains(dohURL, "dns.google") {
		// Switch to the JSON API endpoint
		dohURL = "https://dns.google/resolve"
		params.Add("name", hostname)
	} else {
		// Cloudflare uses the same endpoint with 'name' parameter
		params.Add("name", hostname)
	}
	params.Add("type", fmt.Sprintf("%d", recordType))

	req, err := http.NewRequestWithContext(context.Background(), "GET", dohURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DNS query failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, err
	}

	return &dnsResp, nil
}
