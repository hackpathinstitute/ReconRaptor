"""
Report Generation Module for ReconRaptor
Handles creation and formatting of scan reports
"""

import os
import json
from datetime import datetime
from typing import Dict, Any
from termcolor import colored

class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str): Directory to store reports
        """
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = os.path.join(output_dir, f"scan_{self.timestamp}")
        
    def setup_report_directory(self) -> None:
        """Create the report directory if it doesn't exist."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            print(colored(f"\n[+] Created report directory: {self.report_dir}", "green"))
        except Exception as e:
            print(colored(f"\n[!] Error creating report directory: {str(e)}", "red"))
            raise
            
    def generate_website_info_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate the website information report.
        
        Args:
            scan_results (Dict[str, Any]): Results from the website scanner
            
        Returns:
            str: Path to the generated report file
        """
        report_file = os.path.join(self.report_dir, "website_info.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 50 + "\n")
                f.write("WEBSITE INFORMATION SCAN REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target URL: {scan_results['target_url']}\n")
                f.write(f"IP Address: {scan_results['ip_address']}\n\n")
                
                f.write("SERVER INFORMATION:\n")
                f.write("-" * 20 + "\n")
                for key, value in scan_results['server_info'].items():
                    f.write(f"{key}: {value}\n")
                
                f.write("\nDETECTED TECHNOLOGIES:\n")
                f.write("-" * 20 + "\n")
                for tech in scan_results['technologies']:
                    f.write(f"- {tech}\n")
                    
            return report_file
        except Exception as e:
            print(colored(f"\n[!] Error generating website info report: {str(e)}", "red"))
            raise
            
    def generate_directory_scan_report(self, directories: Dict[str, Any]) -> str:
        """
        Generate the directory scanning report.
        
        Args:
            directories (Dict[str, Any]): Results from directory bruteforcing
            
        Returns:
            str: Path to the generated report file
        """
        report_file = os.path.join(self.report_dir, "directories.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 50 + "\n")
                f.write("DIRECTORY SCAN REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Directories Found: {len(directories)}\n\n")
                
                for path, details in directories.items():
                    f.write("-" * 40 + "\n")
                    f.write(f"Path: {path}\n")
                    f.write(f"Status Code: {details.get('status_code', 'N/A')}\n")
                    f.write(f"Content Length: {details.get('content_length', 'N/A')}\n")
                    f.write(f"Title: {details.get('title', 'N/A')}\n")
                    
            return report_file
        except Exception as e:
            print(colored(f"\n[!] Error generating directory scan report: {str(e)}", "red"))
            raise
            
    def generate_vulnerability_report(self, vulnerabilities: Dict[str, Any]) -> str:
        """
        Generate the vulnerability scan report.
        
        Args:
            vulnerabilities (Dict[str, Any]): Results from vulnerability scanning
            
        Returns:
            str: Path to the generated report file
        """
        report_file = os.path.join(self.report_dir, "vulnerabilities.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 50 + "\n")
                f.write("VULNERABILITY SCAN REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if not vulnerabilities:
                    f.write("No vulnerabilities detected.\n")
                else:
                    for vuln_type, details in vulnerabilities.items():
                        f.write("-" * 40 + "\n")
                        f.write(f"Type: {vuln_type}\n")
                        f.write(f"Severity: {details.get('severity', 'Unknown')}\n")
                        f.write(f"Description: {details.get('description', 'N/A')}\n")
                        f.write(f"Location: {details.get('location', 'N/A')}\n")
                        f.write(f"Recommendation: {details.get('recommendation', 'N/A')}\n\n")
                    
            return report_file
        except Exception as e:
            print(colored(f"\n[!] Error generating vulnerability report: {str(e)}", "red"))
            raise
            
    def generate_summary_report(self, all_results: Dict[str, Any]) -> str:
        """
        Generate a summary report of all scans.
        
        Args:
            all_results (Dict[str, Any]): Combined results from all scans
            
        Returns:
            str: Path to the generated report file
        """
        report_file = os.path.join(self.report_dir, "summary.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 50 + "\n")
                f.write("RECONRAPTOR SCAN SUMMARY\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {all_results.get('target_url', 'N/A')}\n\n")
                
                f.write("SCAN MODULES EXECUTED:\n")
                f.write("-" * 20 + "\n")
                modules = all_results.get('modules_executed', [])
                for module in modules:
                    f.write(f"- {module}\n")
                
                f.write("\nKEY FINDINGS:\n")
                f.write("-" * 20 + "\n")
                findings = all_results.get('key_findings', {})
                for category, count in findings.items():
                    f.write(f"{category}: {count}\n")
                
                f.write("\nREPORT FILES:\n")
                f.write("-" * 20 + "\n")
                for file in os.listdir(self.report_dir):
                    if file != "summary.txt":
                        f.write(f"- {file}\n")
                    
            return report_file
        except Exception as e:
            print(colored(f"\n[!] Error generating summary report: {str(e)}", "red"))
            raise
            
    def save_raw_results(self, results: Dict[str, Any]) -> str:
        """
        Save raw scan results in JSON format.
        
        Args:
            results (Dict[str, Any]): Raw scan results
            
        Returns:
            str: Path to the JSON file
        """
        json_file = os.path.join(self.report_dir, "raw_results.json")
        
        try:
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=4)
            return json_file
        except Exception as e:
            print(colored(f"\n[!] Error saving raw results: {str(e)}", "red"))
            raise
            
    def display_report_location(self) -> None:
        """Display the location of generated reports."""
        print(colored("\n[+] Reports generated successfully!", "green"))
        print(colored(f"[+] Report location: {self.report_dir}", "green"))
        print(colored("[+] Generated files:", "green"))
        for file in os.listdir(self.report_dir):
            print(colored(f"    - {file}", "cyan")) 