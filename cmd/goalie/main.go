package main

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed ip_owners.csv dns_providers.txt
var embeddedData embed.FS

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
	file, err := embeddedData.Open("ip_owners.csv")
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
	file, err := embeddedData.Open("dns_providers.txt")
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

func main() {
	startTime := time.Now()
	provider := flag.String("provider", "google", "DNS provider (cloudflare or google)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: goalie [--provider=cloudflare|google] <hostname>")
		os.Exit(1)
	}

	// Load IP ownership information from embedded data
	ipBlocks, err := loadEmbeddedIPOwners()
	if err != nil {
		fmt.Printf("Warning: couldn't load embedded IP owners data: %v\n", err)
		ipBlocks = []IPBlock{}
	}

	// Load DNS provider information from embedded data
	dnsProviders, err := loadDNSProviders()
	if err != nil {
		fmt.Printf("Warning: couldn't load DNS providers data: %v\n", err)
		dnsProviders = []DNSProvider{}
	}

	hostname := args[0]
	dohURL := cloudflareDoH
	if *provider == "google" {
		dohURL = googleDoH
	}

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

	// Process results as they arrive
	for result := range results {
		fmt.Printf("\n=== %s Records for %s ===\n", result.RecordName, hostname)

		if result.Error != nil {
			fmt.Printf("Error querying %s records: %v\n", result.RecordName, result.Error)
			continue
		}

		if len(result.Response.Answer) == 0 {
			fmt.Printf("No %s records found\n", result.RecordName)
			continue
		}

		for _, answer := range result.Response.Answer {
			// For A records (IPv4) and AAAA records (IPv6), try to determine the owner
			if (result.RecordName == "A" || result.RecordName == "AAAA") && len(ipBlocks) > 0 {
				owner := findIPOwner(answer.Data, ipBlocks)
				if owner != "Unknown" {
					fmt.Printf("%s (%s)\n", answer.Data, owner)
				} else {
					fmt.Printf("%s\n", answer.Data)
				}
			} else if (result.RecordName == "MX" || result.RecordName == "NS" || result.RecordName == "TXT") && len(dnsProviders) > 0 {
				provider := identifyDNSProvider(answer.Data, result.RecordName, dnsProviders)
				if provider != "" {
					fmt.Printf("%s (%s)\n", answer.Data, provider)
				} else {
					fmt.Printf("%s\n", answer.Data)
				}
			} else {
				fmt.Printf("%s\n", answer.Data)
			}
		}
	}

	elapsed := time.Since(startTime)
	fmt.Printf("\nTotal query time: %s\n", elapsed)
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