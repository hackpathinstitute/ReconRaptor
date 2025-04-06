"""
Host Discovery Module for ReconRaptor
Handles network host discovery using various Nmap techniques
"""

import nmap
import ipaddress
from typing import Dict, List, Any
from termcolor import colored

class HostDiscovery:
    def __init__(self):
        """Initialize the host discovery scanner."""
        self.nm = nmap.PortScanner()
        
    def is_valid_network(self, network: str) -> bool:
        """
        Validate if the given network is a valid CIDR or IP range.
        
        Args:
            network (str): Network in CIDR (e.g., '192.168.1.0/24') or range format (e.g., '192.168.1.1-254')
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            if '-' in network:  # IP range format
                start, end = network.rsplit('.', 1)[1].split('-')
                return (1 <= int(start) <= 255 and 
                       1 <= int(end) <= 255 and 
                       int(start) <= int(end))
            else:  # CIDR format
                ipaddress.ip_network(network)
            return True
        except (ValueError, AttributeError):
            return False

    def discover_hosts(self, target_network: str, discovery_type: str = "all") -> Dict[str, Any]:
        """
        Perform host discovery on the target network.
        
        Args:
            target_network (str): Target network in CIDR or range format
            discovery_type (str): Type of discovery ('ping', 'arp', 'all')
            
        Returns:
            Dict[str, Any]: Discovery results
        """
        if not self.is_valid_network(target_network):
            raise ValueError(f"Invalid network format: {target_network}")
            
        discovery_types = {
            "ping": "-sn -PE -n",  # ICMP Echo
            "arp": "-sn -PR",      # ARP Scan
            "syn": "-sn -PS",      # TCP SYN Ping
            "ack": "-sn -PA",      # TCP ACK Ping
            "udp": "-sn -PU",      # UDP Ping
            "all": "-sn -PE -PS21,22,23,25,80,443,3389 -PA80,443 -PU40125"  # Comprehensive
        }
        
        if discovery_type not in discovery_types:
            raise ValueError(f"Invalid discovery type. Must be one of: {', '.join(discovery_types.keys())}")
            
        try:
            print(colored(f"\n[*] Starting host discovery on {target_network}", "blue"))
            print(colored(f"[*] Using discovery type: {discovery_type}", "blue"))
            
            # Perform the scan
            self.nm.scan(hosts=target_network, arguments=discovery_types[discovery_type])
            
            # Process results
            hosts_list = []
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "hostname": self.nm[host].hostname() if self.nm[host].hostname() else "Unknown"
                }
                
                # Get MAC address if available
                if 'mac' in self.nm[host]['addresses']:
                    host_info["mac"] = self.nm[host]['addresses']['mac']
                    if 'vendor' in self.nm[host]:
                        host_info["vendor"] = self.nm[host]['vendor'].get(host_info["mac"], "Unknown")
                
                hosts_list.append(host_info)
            
            results = {
                "target_network": target_network,
                "discovery_type": discovery_type,
                "total_hosts": len(hosts_list),
                "hosts_up": len([h for h in hosts_list if h["status"] == "up"]),
                "scan_stats": self.nm.scanstats(),
                "hosts": hosts_list
            }
            
            return results
            
        except Exception as e:
            print(colored(f"[!] Error during host discovery: {str(e)}", "red"))
            return {
                "target_network": target_network,
                "error": str(e)
            }
    
    def display_results(self, results: Dict[str, Any]) -> None:
        """
        Display host discovery results in a formatted way.
        
        Args:
            results (Dict[str, Any]): Discovery results to display
        """
        if "error" in results:
            print(colored(f"\n[!] Error: {results['error']}", "red"))
            return
            
        print(colored("\n[+] Host Discovery Results", "green"))
        print(colored("=" * 60, "cyan"))
        
        print(colored(f"\nTarget Network: {results['target_network']}", "yellow"))
        print(colored(f"Discovery Type: {results['discovery_type']}", "yellow"))
        print(colored(f"Total Hosts Scanned: {results['total_hosts']}", "yellow"))
        print(colored(f"Hosts Up: {results['hosts_up']}", "yellow"))
        
        if results.get("scan_stats"):
            print(colored("\nScan Statistics:", "yellow"))
            for key, value in results["scan_stats"].items():
                print(f"{key}: {value}")
        
        if results.get("hosts"):
            print(colored("\nDiscovered Hosts:", "yellow"))
            print(colored("-" * 60, "cyan"))
            
            for host in results["hosts"]:
                if host["status"] == "up":
                    print(f"\nIP Address: {host['ip']}")
                    print(f"Status: {host['status']}")
                    print(f"Hostname: {host['hostname']}")
                    if "mac" in host:
                        print(f"MAC Address: {host['mac']}")
                        if "vendor" in host:
                            print(f"Vendor: {host['vendor']}")
                    print(colored("-" * 30, "cyan")) 