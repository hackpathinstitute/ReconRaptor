#!/usr/bin/env python3
"""
ReconRaptor - Web Application Penetration Testing Tool
Main entry point for the program.
"""

import sys
import argparse
from termcolor import colored
from reconraptor.scanner import WebsiteScanner
from reconraptor.report import ReportGenerator
from reconraptor.network_scanner import NetworkScanner
from reconraptor.host_discovery import HostDiscovery
from urllib.parse import urlparse

def display_banner():
    """Display the ReconRaptor banner and disclaimer."""
    banner = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██╔══██║██╔══██╗   ██║   ██║   ██║██╔══██╗
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
    """
    print(colored(banner, "cyan"))
    print(colored("=" * 80, "cyan"))
    print(colored("ReconRaptor - Web Application Penetration Testing Tool", "yellow"))
    print(colored("Version: 1.0.0", "yellow"))
    print(colored("=" * 80, "cyan"))
    
    disclaimer = """
    DISCLAIMER:
    This tool is for educational and authorized penetration testing purposes ONLY.
    Unauthorized use of this tool against systems you do not own or have explicit
    permission to test is illegal and unethical.
    
    By using this tool, you agree to:
    1. Use it only for legal and authorized testing
    2. Not use it for malicious purposes
    3. Take full responsibility for your actions
    
    Type 'I AGREE' to proceed or press Ctrl+C to exit.
    """
    print(colored(disclaimer, "red"))
    
def get_user_agreement() -> bool:
    """Get user agreement to the disclaimer."""
    while True:
        agreement = input(colored("\nDo you agree? (Type 'I AGREE' or 'exit'): ", "yellow"))
        if agreement.upper() == "I AGREE":
            return True
        elif agreement.lower() == "exit":
            return False
        else:
            print(colored("Invalid input. Please type 'I AGREE' or 'exit'.", "red"))

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ReconRaptor - Web Application Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        "target",
        help="Target URL or network to scan (e.g., https://example.com or 192.168.1.0/24)"
    )
    
    # Optional arguments
    parser.add_argument(
        "--wordlist",
        help="Path to wordlist file for directory brute-forcing"
    )
    parser.add_argument(
        "--login-url",
        help="Login URL for brute-force testing"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--output",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--ports",
        default="21-23,25,53,80,110,139,443,445,3306,3389",
        help="Ports to scan (default: common ports)"
    )
    # Add new network scanning options
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Enable aggressive scanning mode (includes OS detection and NSE scripts)"
    )
    parser.add_argument(
        "--skip-web",
        action="store_true",
        help="Skip web application scanning"
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip network scanning"
    )
    # Add new host discovery options
    parser.add_argument(
        "--discovery",
        choices=["ping", "arp", "syn", "ack", "udp", "all"],
        default="all",
        help="Host discovery method (default: all)"
    )
    parser.add_argument(
        "--network-scan",
        action="store_true",
        help="Treat target as a network for host discovery"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner display"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ReconRaptor 1.0.0"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for ReconRaptor."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Display banner and get user agreement
        if not args.no_banner:
            display_banner()
            if not get_user_agreement():
                print(colored("\nExiting...", "yellow"))
                sys.exit(0)
        
        # Initialize report generator
        report_gen = ReportGenerator(args.output)
        report_gen.setup_report_directory()
        
        # Track executed modules and findings
        modules_executed = []
        key_findings = {}
        
        # Initialize scan results
        web_scan_results = {}
        net_scan_results = {}
        host_discovery_results = {}
        
        # Perform host discovery if network scan is requested
        if args.network_scan:
            print(colored(f"\n[+] Starting host discovery on network: {args.target}", "green"))
            host_discovery = HostDiscovery()
            host_discovery_results = host_discovery.discover_hosts(args.target, args.discovery)
            host_discovery.display_results(host_discovery_results)
            modules_executed.append("Host Discovery")
            
            # If hosts were found, scan each one
            if host_discovery_results.get("hosts"):
                up_hosts = [h["ip"] for h in host_discovery_results["hosts"] if h["status"] == "up"]
                if up_hosts and not args.skip_network:
                    print(colored(f"\n[+] Scanning discovered hosts: {len(up_hosts)} hosts", "green"))
                    for host in up_hosts:
                        print(colored(f"\n[*] Scanning host: {host}", "blue"))
                        net_scanner = NetworkScanner(host, args.ports)
                        host_results = net_scanner.scan_host(aggressive=args.aggressive)
                        net_scan_results[host] = host_results
                        net_scanner.display_results(host_results)
        else:
            # Get target hostname for single host scan
            target_host = urlparse(args.target).netloc or args.target
            
            # Perform network scanning if not skipped
            if not args.skip_network:
                print(colored(f"\n[+] Starting network scan for: {target_host}", "green"))
                net_scanner = NetworkScanner(target_host, args.ports)
                net_scan_results = net_scanner.scan_host(aggressive=args.aggressive)
                net_scanner.display_results(net_scan_results)
                modules_executed.append("Network Scanner")
                
                if args.aggressive:
                    modules_executed.append("Advanced Network Scanner")
            
            # Perform web scanning if not skipped
            if not args.skip_web and urlparse(args.target).scheme:
                print(colored(f"\n[+] Starting web scan for: {args.target}", "green"))
                scanner = WebsiteScanner(args.target)
                web_scan_results = scanner.scan()
                scanner.display_results()
                modules_executed.append("Website Information Scanner")
        
        # Generate reports
        if web_scan_results:
            report_gen.generate_website_info_report(web_scan_results)
        
        # TODO: Add directory brute-forcing
        if args.wordlist:
            print(colored("\n[!] Directory brute-forcing module coming soon!", "yellow"))
            modules_executed.append("Directory Bruteforce (Planned)")
        
        # TODO: Add login brute-forcing
        if args.login_url:
            print(colored("\n[!] Login brute-forcing module coming soon!", "yellow"))
            modules_executed.append("Login Bruteforce (Planned)")
        
        # TODO: Add vulnerability scanning
        print(colored("\n[!] Vulnerability scanning module coming soon!", "yellow"))
        modules_executed.append("Vulnerability Scanner (Planned)")
        
        # Prepare results for summary report
        all_results = {
            "target": args.target,
            "modules_executed": modules_executed,
            "key_findings": {
                "Technologies Detected": len(web_scan_results.get('technologies', [])) if web_scan_results else 0,
                "Server Information": bool(web_scan_results.get('server_info', {})) if web_scan_results else False,
                "IP Address": bool(web_scan_results.get('ip_address', '')) if web_scan_results else False,
                "Hosts Discovered": host_discovery_results.get("hosts_up", 0) if host_discovery_results else 0,
                "Networks Scanned": 1 if args.network_scan else 0,
                "Total Open Ports": sum(len([p for p in scan.get('services', []) if p['state'] == 'open']) 
                                     for scan in ([net_scan_results] if isinstance(net_scan_results, dict) 
                                                else net_scan_results.values())),
                "OS Detection": any(scan.get('os_detection', {}) for scan in ([net_scan_results] if isinstance(net_scan_results, dict) 
                                                                            else net_scan_results.values())),
                "Script Results": any(scan.get('script_results', {}) for scan in ([net_scan_results] if isinstance(net_scan_results, dict) 
                                                                                else net_scan_results.values()))
            }
        }
        
        # Generate summary report
        report_gen.generate_summary_report(all_results)
        
        # Save raw results
        combined_results = {
            "web_scan": web_scan_results,
            "network_scan": net_scan_results,
            "host_discovery": host_discovery_results
        }
        report_gen.save_raw_results(combined_results)
        
        # Display report location
        report_gen.display_report_location()
        
    except KeyboardInterrupt:
        print(colored("\n\n[!] Scan interrupted by user.", "red"))
        sys.exit(1)
    except Exception as e:
        print(colored(f"\n[!] Error: {str(e)}", "red"))
        sys.exit(1)

if __name__ == "__main__":
    main() 