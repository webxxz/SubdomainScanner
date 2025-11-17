# Advanced Subdomain Scanner

A comprehensive Python-based subdomain enumeration tool designed for bug bounty hunting and authorized security testing. This scanner uses multiple techniques to discover subdomains deeply and thoroughly.

## Disclaimer

**IMPORTANT: This tool is for authorized security testing only. Only use on domains you have explicit permission to test, such as:**
- Domains within scope of bug bounty programs
- Your own domains and infrastructure
- Authorized penetration testing engagements
- Educational purposes in controlled lab environments

Unauthorized scanning may be illegal in your jurisdiction.

## Features

### Core Enumeration Techniques

1. **Certificate Transparency Logs**
   - Queries crt.sh for historical SSL/TLS certificates
   - Discovers subdomains from certificate records
   - Fast and efficient passive reconnaissance

2. **DNS Brute Force**
   - Multi-threaded subdomain brute forcing
   - Uses custom or built-in wordlist
   - Multiple DNS resolver support for reliability
   - Configurable threads and timeout

3. **DNS Zone Transfer (AXFR)**
   - Attempts zone transfer on all nameservers
   - Discovers all DNS records if misconfigured
   - Automatic nameserver enumeration

4. **Subdomain Permutations** (Deep Mode)
   - Generates intelligent subdomain variations
   - Combines discovered subdomains with common keywords
   - Finds dev, staging, test, and other environments

5. **Reverse DNS Lookups** (Deep Mode)
   - Performs reverse DNS on discovered IP addresses
   - Finds additional subdomains hosted on same infrastructure

6. **HTTP/HTTPS Probing**
   - Tests all discovered subdomains for live web services
   - Extracts HTTP status codes and page titles
   - Identifies actively responding subdomains

7. **Wildcard Detection**
   - Automatically detects wildcard DNS records
   - Warns about potential false positives
   - Helps filter results

### Advanced Features

- **Multi-threaded**: Configurable thread count for optimal performance
- **Multiple DNS Resolvers**: Uses Google, Cloudflare, Quad9, and OpenDNS for redundancy
- **Multiple Output Formats**: Results saved as TXT, JSON, and CSV
- **Colored Output**: Easy-to-read terminal output with color coding
- **Progress Tracking**: Real-time discovery notifications
- **Deep Scan Mode**: Additional permutation and reverse DNS checks
- **Built-in Wordlist**: Default wordlist with 200+ common subdomains

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install dnspython requests urllib3
```

## Usage

### Basic Scan

```bash
python subdomain_scanner.py -d example.com
```

### With Custom Wordlist

```bash
python subdomain_scanner.py -d example.com -w /path/to/wordlist.txt
```

### Deep Scan (Recommended for Bug Bounty)

```bash
python subdomain_scanner.py -d example.com --deep -w wordlist.txt -t 100
```

### Save Results

```bash
python subdomain_scanner.py -d example.com -o results
```

This creates three files:
- `results_YYYYMMDD_HHMMSS.txt` - Plain text list
- `results_YYYYMMDD_HHMMSS.json` - JSON format with metadata
- `results_YYYYMMDD_HHMMSS.csv` - CSV format with IP addresses

### Full Example

```bash
python subdomain_scanner.py -d example.com -w subdomains.txt --deep -t 200 -o scan_results
```

## Command-Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| --domain | -d | Yes | Target domain (e.g., example.com) |
| --wordlist | -w | No | Path to subdomain wordlist file |
| --threads | -t | No | Number of threads (default: 50) |
| --timeout | | No | DNS timeout in seconds (default: 3) |
| --output | -o | No | Output file prefix for results |
| --deep | | No | Enable deep scan mode (permutations, reverse DNS) |

## Scan Techniques Explained

### 1. Certificate Transparency (Passive)

Queries public CT logs for SSL/TLS certificates issued for the domain. This is:
- Completely passive (no direct interaction with target)
- Very fast
- Often finds old/forgotten subdomains
- No rate limiting concerns

### 2. DNS Brute Force (Active)

Tests subdomains from a wordlist by making DNS queries:
- Configurable thread count for speed
- Uses multiple DNS resolvers for reliability
- Can be detected by target's DNS infrastructure
- Effectiveness depends on wordlist quality

### 3. DNS Zone Transfer (Active)

Attempts to download entire DNS zone file:
- Only works if DNS server is misconfigured
- Rare but extremely valuable when successful
- Provides complete subdomain list
- Completely legitimate DNS operation

### 4. Subdomain Permutations (Active - Deep Mode)

Creates variations of discovered subdomains:
- Combines base names with keywords (dev, api, test, etc.)
- Finds environment-specific instances
- Can significantly increase scan time
- Useful for finding staging/development environments

### 5. Reverse DNS (Active - Deep Mode)

Performs reverse lookups on discovered IP addresses:
- Finds additional subdomains on same infrastructure
- Useful for shared hosting environments
- Can discover related services

### 6. HTTP Probing (Active)

Tests HTTP/HTTPS on all discovered subdomains:
- Identifies live web services
- Extracts titles and status codes
- Helps prioritize targets for further testing
- Generates significant traffic

## Recommended Wordlists

The scanner includes a built-in wordlist, but for comprehensive scans, consider:

- **SecLists**: https://github.com/danielmiessler/SecLists
  - `Discovery/DNS/subdomains-top1million-*.txt`

- **Assetnote Wordlists**: https://wordlists.assetnote.io/
  - `best-dns-wordlist.txt`

- **jhaddix All**: https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056

## Performance Tips

1. **Start with Certificate Transparency**: It's passive and fast
2. **Use appropriate thread count**:
   - Start with 50 threads
   - Increase to 100-200 for faster scans
   - Be cautious with very high values (may trigger rate limiting)
3. **Use quality wordlists**: Larger isn't always better
4. **Deep mode for thorough scans**: Use when you need maximum coverage
5. **Save results**: Always use `-o` to preserve findings

## Output Formats

### Text File (.txt)
```
Subdomain Scan Results for example.com
Scan Date: 2024-01-15 10:30:00
Total Subdomains Found: 45
Live Subdomains: 32

============================================================

api.example.com [LIVE]
dev.example.com [LIVE]
mail.example.com
staging.example.com [LIVE]
www.example.com [LIVE]
```

### JSON File (.json)
```json
{
    "domain": "example.com",
    "scan_date": "2024-01-15 10:30:00",
    "total_subdomains": 45,
    "live_subdomains": 32,
    "subdomains": ["api.example.com", "dev.example.com", ...],
    "live": ["api.example.com", "dev.example.com", ...]
}
```

### CSV File (.csv)
```csv
Subdomain,Status,IP Addresses
api.example.com,Live,192.0.2.1
dev.example.com,Live,192.0.2.2
mail.example.com,Found,192.0.2.3
```

## Troubleshooting

### "No module named 'dns'"
```bash
pip install dnspython
```

### Slow Scanning
- Reduce thread count if network is unstable
- Increase timeout if many timeouts occur
- Use smaller wordlist for testing

### Many False Positives
- Wildcard DNS is likely enabled
- The scanner will warn you about this
- Use HTTP probing to verify live subdomains
- Consider filtering results manually

### Permission Denied Errors (Linux/Mac)
```bash
chmod +x subdomain_scanner.py
python3 subdomain_scanner.py -d example.com
```

## Integration with Other Tools

### Pipe to Other Tools

```bash
# Extract subdomains to file
python subdomain_scanner.py -d example.com -o results
cat results_*.txt | grep -v "^[=#]" | grep "\[LIVE\]" | cut -d' ' -f1 > live_subs.txt

# Use with nmap
nmap -iL live_subs.txt -p 80,443,8080,8443

# Use with httpx
cat results_*.txt | grep "\[LIVE\]" | cut -d' ' -f1 | httpx -title -status-code
```

## Comparison with Other Tools

| Feature | This Scanner | Sublist3r | Amass | Subfinder |
|---------|-------------|-----------|-------|-----------|
| Certificate Transparency | ✓ | ✓ | ✓ | ✓ |
| DNS Brute Force | ✓ | ✓ | ✓ | ✓ |
| Zone Transfer | ✓ | ✗ | ✓ | ✗ |
| Permutations | ✓ | ✗ | ✓ | ✗ |
| HTTP Probing | ✓ | ✗ | ✓ | ✗ |
| Reverse DNS | ✓ | ✗ | ✓ | ✗ |
| Multiple Output Formats | ✓ | ✗ | ✓ | ✓ |
| Built-in Wordlist | ✓ | ✗ | ✗ | ✗ |

## Bug Bounty Tips

1. **Always check program scope**: Verify subdomain is in-scope before testing
2. **Save all results**: You may need them for reports
3. **Look for forgotten subdomains**: Old dev/staging environments often have issues
4. **Check for subdomain takeovers**: Test if subdomain points to unclaimed service
5. **Combine with other recon**: Use results with port scanning, screenshot tools
6. **Monitor for new subdomains**: Re-scan periodically to find new assets
7. **Check for sensitive info**: Look for admin panels, dev portals, internal tools

## Legal and Ethical Considerations

- Always obtain proper authorization before scanning
- Respect rate limits and don't cause service disruption
- Follow bug bounty program rules and scope
- Don't use findings for malicious purposes
- Report vulnerabilities responsibly
- Keep discovered information confidential

## Contributing

Suggestions and improvements welcome. Consider adding:
- Additional passive enumeration sources
- API integrations (Shodan, SecurityTrails, etc.)
- Screenshot capability
- Subdomain takeover detection
- Port scanning integration

## License

This tool is provided for educational and authorized testing purposes only.

## Acknowledgments

- Certificate Transparency logs (crt.sh)
- Public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS)
- Bug bounty community for reconnaissance techniques

## Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all dependencies are installed
3. Test with a known domain first
4. Check your Python version (3.7+ required)

## Version History

- v2.0 - Current release with all advanced features
- Multi-technique enumeration
- Deep scan mode
- HTTP probing
- Multiple output formats
- Wildcard detection

---

**Remember: Only scan domains you have permission to test!**
