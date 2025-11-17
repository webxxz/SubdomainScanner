#!/usr/bin/env python3
"""
Advanced Subdomain Scanner for Bug Bounty Programs
Disclaimer: Only use on domains you have explicit permission to test
"""

import argparse
import asyncio
import json
import csv
import dns.resolver
import dns.zone
import dns.query
import requests
import re
import itertools
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from datetime import datetime
import sys
from typing import Set, List, Dict
import socket

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SubdomainScanner:
    def __init__(self, domain, wordlist=None, threads=50, timeout=3, output=None, deep=False):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.deep = deep
        self.subdomains = set()
        self.live_subdomains = set()
        self.resolvers = self.load_resolvers()

    def load_resolvers(self):
        """Load multiple DNS resolvers for redundancy"""
        return [
            '8.8.8.8',      # Google
            '8.8.4.4',      # Google
            '1.1.1.1',      # Cloudflare
            '1.0.0.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222', # OpenDNS
        ]

    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════╗
║     Advanced Subdomain Scanner v2.0               ║
║     Bug Bounty Edition                            ║
╚═══════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKBLUE}[*] Target Domain: {Colors.BOLD}{self.domain}{Colors.ENDC}
{Colors.OKBLUE}[*] Threads: {self.threads}{Colors.ENDC}
{Colors.OKBLUE}[*] Deep Scan: {self.deep}{Colors.ENDC}
{Colors.OKBLUE}[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}
"""
        print(banner)

    def check_dns(self, subdomain):
        """Check if subdomain resolves via DNS"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for dns_server in self.resolvers:
            resolver.nameservers = [dns_server]
            try:
                answers = resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                return True, ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                continue
            except Exception:
                continue
        return False, []

    def dns_bruteforce(self):
        """Brute force subdomains using wordlist"""
        print(f"\n{Colors.HEADER}[+] Starting DNS Brute Force...{Colors.ENDC}")

        if not self.wordlist:
            print(f"{Colors.WARNING}[!] No wordlist provided, using default list{Colors.ENDC}")
            wordlist = self.get_default_wordlist()
        else:
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Colors.FAIL}[!] Wordlist file not found: {self.wordlist}{Colors.ENDC}")
                return

        found_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for word in wordlist:
                subdomain = f"{word}.{self.domain}"
                futures[executor.submit(self.check_dns, subdomain)] = subdomain

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    exists, ips = future.result()
                    if exists:
                        self.subdomains.add(subdomain)
                        found_count += 1
                        print(f"{Colors.OKGREEN}[✓] Found: {subdomain} -> {', '.join(ips)}{Colors.ENDC}")
                except Exception:
                    pass

        print(f"{Colors.OKBLUE}[*] DNS Brute Force completed: {found_count} subdomains found{Colors.ENDC}")

    def get_default_wordlist(self):
        """Return default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search',
            'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites',
            'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
            'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
            'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2',
            'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway',
            'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios',
            'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql',
            'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail',
            's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image', 'members', 'poczta', 's1',
            'meet', 'preview', 'fr', 'cloudflare-resolve-to', 'dev2', 'photo', 'jabber',
            'legacy', 'go', 'es', 'ssh', 'redmine', 'partner', 'vps', 'server1', 'sv',
            'ns6', 'webmail2', 'av', 'community', 'cacti', 'time', 'sftp', 'lib', 'facebook',
            'www5', 'smtp1', 'feeds', 'w', 'games', 'ts', 'alumni', 'dl', 's2', 'phpmyadmin',
            'archive', 'cn', 'tools', 'stream', 'projects', 'elearning', 'im', 'iphone',
            'control', 'voip', 'test1', 'ws', 'rss', 'sp', 'wwww', 'vpn2', 'jira', 'list',
            'connect', 'gallery', 'billing', 'mailer', 'update', 'pda', 'game', 'ns0',
            'testing', 'sandbox', 'job', 'events', 'dialin', 'ml', 'fb', 'videos', 'music',
            'a', 'partners', 'mailhost', 'downloads', 'reports', 'ca', 'router', 'speedtest',
            'local', 'training', 'edu', 'bugs', 'manage', 's3', 'status', 'host2', 'ww2',
            'marketing', 'conference', 'content', 'network-ip', 'broadcast-ip', 'english',
            'catalog', 'msoid', 'mailinglist', 'redirect', 'ipv6', 'developer', 'dashboard',
            'android', 'atlassian', 'careers', 'cvs', 'faq', 'registration'
        ]

    def certificate_transparency(self):
        """Query Certificate Transparency logs"""
        print(f"\n{Colors.HEADER}[+] Querying Certificate Transparency Logs...{Colors.ENDC}")

        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                found_count = 0
                for entry in data:
                    name_value = entry.get('name_value', '')
                    subdomains = name_value.split('\n')
                    for subdomain in subdomains:
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and subdomain not in self.subdomains:
                            # Remove wildcard
                            subdomain = subdomain.replace('*.', '')
                            if self.is_valid_subdomain(subdomain):
                                self.subdomains.add(subdomain)
                                found_count += 1
                                print(f"{Colors.OKGREEN}[✓] Found: {subdomain}{Colors.ENDC}")

                print(f"{Colors.OKBLUE}[*] Certificate Transparency: {found_count} subdomains found{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] CT Logs error: {str(e)}{Colors.ENDC}")

    def is_valid_subdomain(self, subdomain):
        """Validate subdomain format"""
        if not subdomain or subdomain == self.domain:
            return False
        pattern = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.' + re.escape(self.domain) + '$')
        return bool(pattern.match(subdomain))

    def dns_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        print(f"\n{Colors.HEADER}[+] Attempting DNS Zone Transfer (AXFR)...{Colors.ENDC}")

        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_server)
                    print(f"{Colors.OKBLUE}[*] Trying zone transfer on {ns_server} ({ns_ip}){Colors.ENDC}")

                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))
                    if zone:
                        print(f"{Colors.WARNING}[!] Zone transfer successful on {ns_server}!{Colors.ENDC}")
                        found_count = 0
                        for name, node in zone.nodes.items():
                            subdomain = str(name) + '.' + self.domain
                            if subdomain not in self.subdomains:
                                self.subdomains.add(subdomain)
                                found_count += 1
                                print(f"{Colors.OKGREEN}[✓] Found: {subdomain}{Colors.ENDC}")
                        print(f"{Colors.OKBLUE}[*] Zone transfer: {found_count} subdomains found{Colors.ENDC}")
                        return
                except Exception:
                    pass

            print(f"{Colors.OKBLUE}[*] Zone transfer not allowed or failed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.OKBLUE}[*] Zone transfer check completed{Colors.ENDC}")

    def subdomain_permutations(self):
        """Generate subdomain permutations and alterations"""
        if not self.deep:
            return

        print(f"\n{Colors.HEADER}[+] Generating Subdomain Permutations...{Colors.ENDC}")

        # Common words to combine
        words = ['api', 'dev', 'test', 'staging', 'prod', 'uat', 'qa', 'admin', 'portal',
                 'app', 'mobile', 'web', 'secure', 'vpn', 'remote', 'internal', 'external',
                 'public', 'private', 'v1', 'v2', 'old', 'new', 'backup', 'tmp']

        # Get base subdomains
        base_subdomains = set()
        for subdomain in list(self.subdomains):
            parts = subdomain.replace(f'.{self.domain}', '').split('.')
            base_subdomains.update(parts)

        # Generate permutations
        permutations = set()
        for base in list(base_subdomains)[:20]:  # Limit to avoid explosion
            for word in words:
                permutations.add(f"{base}-{word}.{self.domain}")
                permutations.add(f"{word}-{base}.{self.domain}")
                permutations.add(f"{base}{word}.{self.domain}")
                permutations.add(f"{word}{base}.{self.domain}")

        # Test permutations
        found_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for perm in permutations:
                if perm not in self.subdomains:
                    futures[executor.submit(self.check_dns, perm)] = perm

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    exists, ips = future.result()
                    if exists:
                        self.subdomains.add(subdomain)
                        found_count += 1
                        print(f"{Colors.OKGREEN}[✓] Found: {subdomain} -> {', '.join(ips)}{Colors.ENDC}")
                except Exception:
                    pass

        print(f"{Colors.OKBLUE}[*] Permutations: {found_count} subdomains found{Colors.ENDC}")

    def detect_wildcard(self):
        """Detect wildcard DNS records"""
        print(f"\n{Colors.HEADER}[+] Checking for Wildcard DNS...{Colors.ENDC}")

        random_subdomain = f"random-{int(time.time())}-test.{self.domain}"
        exists, ips = self.check_dns(random_subdomain)

        if exists:
            print(f"{Colors.WARNING}[!] Wildcard DNS detected! IP: {', '.join(ips)}{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Results may include false positives{Colors.ENDC}")
            return True, ips
        else:
            print(f"{Colors.OKBLUE}[*] No wildcard DNS detected{Colors.ENDC}")
            return False, []

    def http_probe(self):
        """Probe subdomains with HTTP/HTTPS to check if they're live"""
        print(f"\n{Colors.HEADER}[+] Probing HTTP/HTTPS on discovered subdomains...{Colors.ENDC}")

        def probe_subdomain(subdomain):
            results = []
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                    results.append({
                        'subdomain': subdomain,
                        'url': url,
                        'status_code': response.status_code,
                        'title': self.extract_title(response.text),
                        'length': len(response.content)
                    })
                    return results
                except requests.exceptions.SSLError:
                    continue
                except Exception:
                    continue
            return results

        live_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_subdomain, sub): sub for sub in self.subdomains}

            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        for result in results:
                            self.live_subdomains.add(result['subdomain'])
                            live_count += 1
                            title = result['title'][:50] if result['title'] else 'N/A'
                            print(f"{Colors.OKGREEN}[✓] Live: {result['url']} [{result['status_code']}] - {title}{Colors.ENDC}")
                except Exception:
                    pass

        print(f"{Colors.OKBLUE}[*] HTTP Probe: {live_count} live subdomains found{Colors.ENDC}")

    def extract_title(self, html):
        """Extract title from HTML"""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def reverse_dns(self):
        """Perform reverse DNS lookups on discovered IPs"""
        if not self.deep:
            return

        print(f"\n{Colors.HEADER}[+] Performing Reverse DNS Lookups...{Colors.ENDC}")

        ips = set()
        for subdomain in self.subdomains:
            exists, ip_list = self.check_dns(subdomain)
            if exists:
                ips.update(ip_list)

        found_count = 0
        for ip in ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if hostname.endswith(self.domain) and hostname not in self.subdomains:
                    self.subdomains.add(hostname)
                    found_count += 1
                    print(f"{Colors.OKGREEN}[✓] Found: {hostname} (reverse DNS from {ip}){Colors.ENDC}")
            except Exception:
                pass

        print(f"{Colors.OKBLUE}[*] Reverse DNS: {found_count} subdomains found{Colors.ENDC}")

    def save_results(self):
        """Save results to file"""
        if not self.output:
            return

        print(f"\n{Colors.HEADER}[+] Saving results...{Colors.ENDC}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save as text
        txt_file = f"{self.output}_{timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write(f"Subdomain Scan Results for {self.domain}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Found: {len(self.subdomains)}\n")
            f.write(f"Live Subdomains: {len(self.live_subdomains)}\n\n")
            f.write("=" * 60 + "\n\n")
            for subdomain in sorted(self.subdomains):
                status = "[LIVE]" if subdomain in self.live_subdomains else ""
                f.write(f"{subdomain} {status}\n")

        # Save as JSON
        json_file = f"{self.output}_{timestamp}.json"
        data = {
            'domain': self.domain,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_subdomains': len(self.subdomains),
            'live_subdomains': len(self.live_subdomains),
            'subdomains': list(self.subdomains),
            'live': list(self.live_subdomains)
        }
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=4)

        # Save as CSV
        csv_file = f"{self.output}_{timestamp}.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'Status', 'IP Addresses'])
            for subdomain in sorted(self.subdomains):
                exists, ips = self.check_dns(subdomain)
                status = 'Live' if subdomain in self.live_subdomains else 'Found'
                writer.writerow([subdomain, status, ', '.join(ips) if ips else ''])

        print(f"{Colors.OKGREEN}[✓] Results saved to:{Colors.ENDC}")
        print(f"    - {txt_file}")
        print(f"    - {json_file}")
        print(f"    - {csv_file}")

    def run(self):
        """Run the complete scan"""
        self.print_banner()

        # Wildcard detection
        is_wildcard, wildcard_ips = self.detect_wildcard()

        # Certificate Transparency (fast, should be first)
        self.certificate_transparency()

        # DNS Zone Transfer
        self.dns_zone_transfer()

        # DNS Brute Force
        self.dns_bruteforce()

        # Subdomain Permutations (only in deep mode)
        self.subdomain_permutations()

        # Reverse DNS (only in deep mode)
        self.reverse_dns()

        # HTTP Probing
        self.http_probe()

        # Print summary
        print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.BOLD}Scan Summary:{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Total Subdomains Found: {len(self.subdomains)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Live Subdomains: {len(self.live_subdomains)}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")

        # Save results
        if self.output:
            self.save_results()

        return self.subdomains, self.live_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Subdomain Scanner for Bug Bounty Programs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_scanner.py -d example.com
  python subdomain_scanner.py -d example.com -w wordlist.txt -t 100
  python subdomain_scanner.py -d example.com --deep -o results
  python subdomain_scanner.py -d example.com -w wordlist.txt --deep -t 200 -o scan_results

Disclaimer:
  This tool is for authorized security testing only.
  Only use on domains you have explicit permission to test.
        """
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to subdomain wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=3, help='DNS timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', help='Output file prefix (results will be saved as txt, json, csv)')
    parser.add_argument('--deep', action='store_true', help='Enable deep scan (permutations, reverse DNS)')

    args = parser.parse_args()

    # Validate domain
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$', args.domain):
        print(f"{Colors.FAIL}[!] Invalid domain format{Colors.ENDC}")
        sys.exit(1)

    # Create scanner and run
    scanner = SubdomainScanner(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        deep=args.deep
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        if scanner.output:
            scanner.save_results()
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    main()
