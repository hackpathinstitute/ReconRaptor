"""
Website Information Scanner Module
This module handles gathering information about target websites including:
- Server headers
- HTTP status
- IP address
- Technology stack
"""

import socket
import re
import httpx
from typing import Dict, List, Optional
from termcolor import colored
from urllib.parse import urlparse

class WebsiteScanner:
    def __init__(self, target_url: str):
        """
        Initialize the WebsiteScanner with a target URL.
        
        Args:
            target_url (str): The URL to scan
        """
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.results: Dict[str, any] = {}
        
    def get_ip_address(self) -> Optional[str]:
        """
        Get the IP address of the target domain.
        
        Returns:
            Optional[str]: IP address if found, None otherwise
        """
        try:
            domain = self.parsed_url.netloc
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
            
    def get_server_info(self) -> Dict[str, str]:
        """
        Get server information from HTTP headers.
        
        Returns:
            Dict[str, str]: Dictionary containing server information
        """
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(self.target_url)
                headers = response.headers
                
                server_info = {
                    'server': headers.get('server', 'Not found'),
                    'x-powered-by': headers.get('x-powered-by', 'Not found'),
                    'content-type': headers.get('content-type', 'Not found'),
                    'status_code': str(response.status_code),
                }
                return server_info
        except Exception as e:
            return {'error': str(e)}
            
    def detect_tech_stack(self) -> List[str]:
        """
        Detect technology stack based on headers and content.
        
        Returns:
            List[str]: List of detected technologies
        """
        technologies = []
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(self.target_url)
                content = response.text.lower()
                headers = response.headers
                
                # Check for common technologies
                if 'php' in headers.get('x-powered-by', '').lower():
                    technologies.append('PHP')
                if 'wordpress' in content:
                    technologies.append('WordPress')
                if 'jquery' in content:
                    technologies.append('jQuery')
                if 'react' in content:
                    technologies.append('React')
                if 'django' in content:
                    technologies.append('Django')
                if 'flask' in content:
                    technologies.append('Flask')
                    
                # Check for common server technologies
                server = headers.get('server', '').lower()
                if 'apache' in server:
                    technologies.append('Apache')
                if 'nginx' in server:
                    technologies.append('Nginx')
                if 'iis' in server:
                    technologies.append('IIS')
                    
        except Exception as e:
            technologies.append(f'Error detecting technologies: {str(e)}')
            
        return technologies
        
    def scan(self) -> Dict[str, any]:
        """
        Perform a complete scan of the target website.
        
        Returns:
            Dict[str, any]: Dictionary containing all scan results
        """
        self.results = {
            'target_url': self.target_url,
            'ip_address': self.get_ip_address(),
            'server_info': self.get_server_info(),
            'technologies': self.detect_tech_stack()
        }
        return self.results
        
    def display_results(self):
        """Display scan results in a formatted way."""
        print(colored("\n[+] Website Information Scanner Results", "green"))
        print(colored("=" * 50, "cyan"))
        
        print(colored("\nTarget URL:", "yellow"), self.results['target_url'])
        print(colored("IP Address:", "yellow"), self.results['ip_address'])
        
        print(colored("\nServer Information:", "yellow"))
        for key, value in self.results['server_info'].items():
            print(f"  {key}: {value}")
            
        print(colored("\nDetected Technologies:", "yellow"))
        for tech in self.results['technologies']:
            print(f"  - {tech}")
            
        print(colored("\n" + "=" * 50, "cyan")) 