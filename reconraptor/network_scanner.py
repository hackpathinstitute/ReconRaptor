"""
Advanced Network Scanning Module for ReconRaptor
Handles comprehensive port scanning, service detection, OS fingerprinting, and NSE scripts
"""

import nmap
import socket
import json
from typing import Dict, Any, List, Optional
from termcolor import colored

class NetworkScanner:
    def __init__(self, target: str, ports: str = "21-23,25,53,80,110,139,443,445,3306,3389"):
        """
        Initialize the network scanner.
        
        Args:
            target (str): Target host/IP to scan
            ports (str): Port range to scan (default: common ports)
        """
        self.target = target
        self.ports = ports
        self.nm = nmap.PortScanner()
        
    def get_ip_from_hostname(self) -> str:
        """Get IP address from hostname."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return self.target

    def perform_ping_scan(self) -> Dict[str, Any]:
        """Perform a ping scan to check host availability."""
        try:
            print(colored("\n[*] Performing ping scan...", "blue"))
            self.nm.scan(hosts=self.target, arguments='-sn -PE -PA21,23,80,3389')
            return {
                "hosts_up": len(self.nm.all_hosts()),
                "scan_stats": self.nm.scanstats(),
                "hosts": self.nm.all_hosts()
            }
        except Exception as e:
            print(colored(f"[!] Ping scan error: {str(e)}", "red"))
            return {}

    def perform_os_detection(self, target_ip: str) -> Dict[str, Any]:
        """
        Perform OS detection on the target.
        
        Args:
            target_ip (str): Target IP address
            
        Returns:
            Dict[str, Any]: OS detection results
        """
        try:
            print(colored("\n[*] Performing OS detection...", "blue"))
            self.nm.scan(hosts=target_ip, arguments='-O --osscan-guess')
            
            if target_ip in self.nm.all_hosts():
                if 'osmatch' in self.nm[target_ip]:
                    return {
                        "os_matches": self.nm[target_ip]['osmatch'],
                        "accuracy": self.nm[target_ip].get('osclass', {}).get('accuracy', 'Unknown')
                    }
            return {}
        except Exception as e:
            print(colored(f"[!] OS detection error: {str(e)}", "red"))
            return {}

    def perform_service_scan(self, target_ip: str) -> List[Dict[str, Any]]:
        """
        Perform detailed service scanning.
        
        Args:
            target_ip (str): Target IP address
            
        Returns:
            List[Dict[str, Any]]: Service scan results
        """
        try:
            print(colored("\n[*] Performing service detection...", "blue"))
            self.nm.scan(
                hosts=target_ip,
                ports=self.ports,
                arguments='-sV -sS --version-intensity 9'
            )
            
            services = []
            if target_ip in self.nm.all_hosts():
                for proto in self.nm[target_ip].all_protocols():
                    ports = self.nm[target_ip][proto].keys()
                    for port in ports:
                        port_info = self.nm[target_ip][proto][port]
                        services.append({
                            "port": port,
                            "protocol": proto,
                            "state": port_info["state"],
                            "service": port_info["name"],
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extrainfo": port_info.get("extrainfo", ""),
                            "cpe": port_info.get("cpe", "")
                        })
            return services
        except Exception as e:
            print(colored(f"[!] Service scan error: {str(e)}", "red"))
            return []

    def perform_script_scan(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
        """
        Perform NSE script scanning.
        
        Args:
            target_ip (str): Target IP address
            ports (List[int]): List of open ports to scan
            
        Returns:
            Dict[str, Any]: Script scan results
        """
        try:
            if not ports:
                return {}
                
            print(colored("\n[*] Performing script scan...", "blue"))
            port_str = ",".join(map(str, ports))
            
            # Run common scripts and vulnerability detection
            self.nm.scan(
                hosts=target_ip,
                ports=port_str,
                arguments='--script=default,vuln,auth,banner,ssl-enum-ciphers'
            )
            
            script_results = {}
            if target_ip in self.nm.all_hosts():
                for port in ports:
                    try:
                        port_scripts = self.nm[target_ip]['tcp'][port].get('script', {})
                        if port_scripts:
                            script_results[str(port)] = port_scripts
                    except KeyError:
                        continue
                        
            return script_results
        except Exception as e:
            print(colored(f"[!] Script scan error: {str(e)}", "red"))
            return {}

    def scan_host(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Perform a comprehensive host scan.
        
        Args:
            aggressive (bool): Whether to perform aggressive scanning
            
        Returns:
            Dict[str, Any]: Comprehensive scan results
        """
        try:
            print(colored(f"\n[+] Starting comprehensive scan on {self.target}", "blue"))
            
            # Convert hostname to IP
            target_ip = self.get_ip_from_hostname()
            
            # Initialize results dictionary
            scan_results = {
                "target": self.target,
                "target_ip": target_ip,
                "timestamp": self.nm.get_nmap_last_output(),
                "ping_scan": {},
                "os_detection": {},
                "services": [],
                "script_results": {}
            }
            
            # Perform ping scan
            scan_results["ping_scan"] = self.perform_ping_scan()
            
            if target_ip in self.nm.all_hosts():
                # Perform OS detection
                scan_results["os_detection"] = self.perform_os_detection(target_ip)
                
                # Perform service scanning
                scan_results["services"] = self.perform_service_scan(target_ip)
                
                # Get list of open ports
                open_ports = [
                    service["port"] for service in scan_results["services"]
                    if service["state"] == "open"
                ]
                
                # Perform script scanning on open ports
                if open_ports:
                    scan_results["script_results"] = self.perform_script_scan(target_ip, open_ports)
                
                # Additional aggressive scanning if requested
                if aggressive:
                    print(colored("\n[*] Performing aggressive scan...", "blue"))
                    self.nm.scan(
                        hosts=target_ip,
                        arguments='-A -T4 --max-retries 2'
                    )
                    
                    # Add any additional findings from aggressive scan
                    if 'hostscript' in self.nm[target_ip]:
                        scan_results["aggressive_results"] = self.nm[target_ip]['hostscript']
            
            return scan_results
            
        except Exception as e:
            print(colored(f"\n[!] Error during scan: {str(e)}", "red"))
            return {
                "target": self.target,
                "target_ip": self.get_ip_from_hostname(),
                "error": str(e)
            }
            
    def display_results(self, results: Dict[str, Any]) -> None:
        """
        Display scan results in a formatted way.
        
        Args:
            results (Dict[str, Any]): Scan results to display
        """
        print(colored("\n[+] Network Scan Results", "green"))
        print(colored("=" * 60, "cyan"))
        
        print(colored(f"\nTarget: {results['target']}", "yellow"))
        print(colored(f"IP Address: {results['target_ip']}", "yellow"))
        
        if "error" in results:
            print(colored(f"\nError: {results['error']}", "red"))
            return
            
        # Display OS Detection Results
        if results.get("os_detection"):
            print(colored("\nOS Detection Results:", "yellow"))
            print(colored("-" * 40, "cyan"))
            for os_match in results["os_detection"].get("os_matches", [])[:3]:
                print(f"OS: {os_match.get('name', 'Unknown')}")
                print(f"Accuracy: {os_match.get('accuracy', 'Unknown')}%")
                print(colored("-" * 30, "cyan"))
            
        # Display Service Information
        if results.get("services"):
            print(colored("\nDiscovered Services:", "yellow"))
            print(colored("-" * 40, "cyan"))
            for service in results["services"]:
                if service["state"] == "open":
                    print(f"Port {service['port']}/{service['protocol']} - {service['state']}")
                    print(f"Service: {service['service']}")
                    if service["product"]:
                        print(f"Product: {service['product']}")
                    if service["version"]:
                        print(f"Version: {service['version']}")
                    if service["extrainfo"]:
                        print(f"Info: {service['extrainfo']}")
                    print(colored("-" * 30, "cyan"))
            
        # Display Script Scan Results
        if results.get("script_results"):
            print(colored("\nScript Scan Results:", "yellow"))
            print(colored("-" * 40, "cyan"))
            for port, scripts in results["script_results"].items():
                print(f"\nPort {port} Script Results:")
                for script_name, output in scripts.items():
                    print(colored(f"\n{script_name}:", "cyan"))
                    print(output)
            
        # Display Aggressive Scan Results if available
        if results.get("aggressive_results"):
            print(colored("\nAggressive Scan Results:", "yellow"))
            print(colored("-" * 40, "cyan"))
            for result in results["aggressive_results"]:
                print(f"\n{result.get('id', 'Unknown Script')}:")
                print(result.get('output', 'No output'))
                
        print(colored("\n" + "=" * 60, "cyan")) 