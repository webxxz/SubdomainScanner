<p align="center">
  <img src="https://raw.githubusercontent.com/webxxz/SubdomainScanner/refs/heads/main/subdomain_scanner.png" width="100%">
</p>

<h1 align="center">⚡ Advanced Subdomain Scanner — Bug Bounty Edition</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-Open-green?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/webxxz/SubdomainScanner?style=for-the-badge">
  <img src="https://img.shields.io/github/forks/webxxz/SubdomainScanner?style=for-the-badge">
  <img src="https://img.shields.io/github/issues/webxxz/SubdomainScanner?style=for-the-badge">
</p>

---

# 📝 Advanced Subdomain Scanner  
A comprehensive Python-based subdomain enumeration tool designed for bug bounty hunting and authorized security testing. This scanner uses multiple techniques to discover subdomains deeply and thoroughly.

---

# ⚠️ Disclaimer  
**IMPORTANT:** This tool is for **authorized security testing only**. Only use on domains you have explicit permission to test, such as:

- Domains within scope of bug bounty programs  
- Your own domains and infrastructure  
- Authorized penetration testing engagements  
- Educational purposes in controlled lab environments  

Unauthorized scanning may be illegal in your jurisdiction.

---

# ✨ Features

## 🔍 Core Enumeration Techniques

### **Certificate Transparency Logs**
- Queries crt.sh for historical SSL/TLS certificates  
- Discovers subdomains from certificate records  
- Fast and efficient passive reconnaissance  

### **DNS Brute Force**
- Multi-threaded subdomain brute forcing  
- Uses custom or built-in wordlist  
- Multiple DNS resolver support for reliability  
- Configurable threads and timeout  

### **DNS Zone Transfer (AXFR)**
- Attempts zone transfer on all nameservers  
- Discovers all DNS records if misconfigured  
- Automatic nameserver enumeration  

### **Subdomain Permutations (Deep Mode)**
- Generates intelligent permutation variations  
- Finds dev, staging, test, QA, backup, and other environments  

### **Reverse DNS Lookups (Deep Mode)**
- Performs reverse lookups on discovered IP addresses  
- Finds subdomains sharing same infrastructure  

### **HTTP/HTTPS Probing**
- Tests all discovered subdomains for live services  
- Extracts HTTP status codes and page titles  
- Identifies actively responding hosts  

### **Wildcard Detection**
- Automatically detects wildcard DNS  
- Warns about false-positive risks  
- Helps filter noisy results  

---

# 🧠 Advanced Features  
- Multi-threaded scanning for speed  
- Multiple DNS resolvers (Google, Cloudflare, Quad9, OpenDNS)  
- Output formats: TXT, JSON, CSV  
- Color-coded output  
- Real-time progress tracking  
- Deep Scan Mode  
- Built-in 200+ common subdomains  

---

# ⚙️ Installation

### **Prerequisites**
- Python **3.7+**
- `pip`

### **Install Dependencies**
```
pip install -r requirements.txt
```

Or manually:

```
pip install dnspython requests urllib3
```

---

# 🚀 Usage

### **Basic Scan**
```
python subdomain_scanner.py -d example.com
```

### **With Custom Wordlist**
```
python subdomain_scanner.py -d example.com -w /path/to/wordlist.txt
```

### **Deep Scan (Bug Bounty Recommended)**
```
python subdomain_scanner.py -d example.com --deep -w wordlist.txt -t 100
```

### **Save Results**
```
python subdomain_scanner.py -d example.com -o results
```

Creates:
- `results_YYYYMMDD_HHMMSS.txt`
- `results_YYYYMMDD_HHMMSS.json`
- `results_YYYYMMDD_HHMMSS.csv`

### **Full Example**
```
python subdomain_scanner.py -d example.com -w subdomains.txt --deep -t 200 -o scan_results
```

---

# 🧾 Command-Line Arguments

| Argument   | Short | Required | Description |
|-----------|--------|----------|-------------|
| `--domain` | `-d` | ✔ Yes | Target domain |
| `--wordlist` | `-w` | No | Path to wordlist |
| `--threads` | `-t` | No | Thread count (default 50) |
| `--timeout` | — | No | DNS timeout (default 3 sec) |
| `--output` | `-o` | No | Output directory prefix |
| `--deep` | — | No | Enable deep mode |

---

# 🔬 Scan Techniques Explained

### **1. Certificate Transparency (Passive)**
- No interaction with target  
- Fast  
- Great for discovering forgotten subdomains  

### **2. DNS Brute Force (Active)**
- Depends on wordlist quality  
- Supports multi-threading and resolvers  

### **3. DNS Zone Transfer (AXFR)**
- Rare but extremely powerful  
- Complete zone file extraction  

### **4. Subdomain Permutations**
- `dev-`, `staging-`, `-test`, etc.  
- Finds environment-specific hosts  

### **5. Reverse DNS**
- Identifies additional assets  
- Reveals hidden subdomains  

### **6. HTTP Probing**
- Determines live vs dead hosts  
- Grabs titles, redirects, status codes  

---

# 📚 Recommended Wordlists

- **SecLists**  
  https://github.com/danielmiessler/SecLists  
- **Assetnote Wordlists**  
  https://wordlists.assetnote.io/  
- **Jhaddix All.txt**  
  https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056  

---

# ⚡ Performance Tips  
- Start with CT logs (fastest)  
- Increase threads gradually (50 → 100 → 200)  
- Avoid very high thread counts on unstable networks  
- Use quality wordlists  
- Always output with `-o` for saving results  
- Use deep mode for maximum coverage  

---

# 📤 Output Formats

### TXT
```
Subdomain Scan Results for example.com
Total Subdomains Found: 45
Live Subdomains: 32
```

### JSON
```json
{
  "domain": "example.com",
  "total_subdomains": 45,
  "live_subdomains": 32
}
```

### CSV
```
Subdomain,Status,IP
api.example.com,Live,192.0.2.1
```

---

# 🔧 Troubleshooting

### ❌ "No module named 'dns'"
```
pip install dnspython
```

### ❌ Slow Scanning
- Reduce threads  
- Increase timeout  
- Use smaller wordlist  

### ❌ Many False Positives
- Wildcard DNS active  
- Use HTTP probing to verify  

### ❌ Permission Denied (Linux/Mac)
```
chmod +x subdomain_scanner.py
python3 subdomain_scanner.py -d example.com
```

---

# 🔗 Integration With Other Tools

### Extract live subdomains
```
cat results_*.txt | grep "[LIVE]" | cut -d' ' -f1 > live_subs.txt
```

### Use with Nmap
```
nmap -iL live_subs.txt -p 80,443,8080,8443
```

### Use with httpx
```
cat live_subs.txt | httpx -title -status-code
```

---

# 🧾 Comparison With Other Tools

| Feature | This Scanner | Sublist3r | Amass | Subfinder |
|--------|--------------|-----------|-------|-----------|
| Certificate Transparency | ✔ | ✔ | ✔ | ✔ |
| DNS Brute Force | ✔ | ✔ | ✔ | ✔ |
| Zone Transfer | ✔ | ✖ | ✔ | ✖ |
| Permutations | ✔ | ✖ | ✔ | ✖ |
| HTTP Probing | ✔ | ✖ | ✔ | ✖ |
| Reverse DNS | ✔ | ✖ | ✔ | ✖ |
| Multiple Output Formats | ✔ | ✖ | ✔ | ✔ |
| Built-in Wordlist | ✔ | ✖ | ✖ | ✖ |

---

# 🏹 Bug Bounty Tips

- Always check target scope  
- Save results for reporting  
- Look for forgotten environments  
- Test for subdomain takeover  
- Combine with screenshot & port scanning  
- Re-scan periodically for new assets  

---

# ⚖️ Legal & Ethical Considerations
- Use only with authorization  
- Respect program rules  
- Avoid causing service disruption  
- Report responsibly  
- Keep findings confidential  

---

# 🤝 Contributing  
Suggestions and improvements welcome. Ideas:

- Additional passive OSINT sources  
- Shodan / SecurityTrails integration  
- Screenshot capability  
- Subdomain takeover detection  
- Port scanning integration  

---

# 📜 License  
This tool is provided for educational and authorized security testing purposes only.

---

# 🙏 Acknowledgments  
- Certificate Transparency (`crt.sh`)  
- Public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS)  
- Bug bounty community  

---

# 🆘 Support  
For issues or questions:
- Check troubleshooting section  
- Ensure dependencies installed  
- Test with known domain  
- Verify Python version (3.7+)

---

# 🕒 Version History  
**v2.0 — Current Release**  
- Multi-technique enumeration  
- Deep mode  
- HTTP probing  
- Multiple outputs  
- Wildcard detection  

---

# 🔐 Final Reminder  
**Only scan domains you have permission to test!**
