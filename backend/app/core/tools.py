"""
4postle Tool Execution Modules
Implements actual tool execution for each scanning phase
"""

import asyncio
import subprocess
import json
import re
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import tempfile
import os
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

from app.core.scanner import Asset, Vulnerability, Severity

class ToolExecutor:
    """Base class for tool execution"""
    
    def __init__(self, temp_dir: str = "/tmp"):
        self.temp_dir = temp_dir
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """Run command with timeout and return output"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return (
                process.returncode,
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore')
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

class PassiveReconTools(ToolExecutor):
    """Tools for Phase 1: Passive Reconnaissance"""
    
    async def run_subfinder(self, target: str) -> List[str]:
        """Execute subfinder for subdomain discovery"""
        output_file = f"{self.temp_dir}/subfinder_{target}.txt"
        cmd = [
            "subfinder",
            "-d", target,
            "-silent",
            "-o", output_file
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            os.unlink(output_file)
            return subdomains
        
        return []
    
    async def run_amass(self, target: str) -> List[str]:
        """Execute amass for passive subdomain discovery"""
        output_file = f"{self.temp_dir}/amass_{target}.txt"
        cmd = [
            "amass", "enum",
            "-passive",
            "-d", target,
            "-o", output_file
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            os.unlink(output_file)
            return subdomains
        
        return []
    
    async def query_crtsh(self, target: str) -> List[str]:
        """Query crt.sh for certificate transparency"""
        if not self.session:
            return []
        
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            async with self.session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for cert in data:
                        name_value = cert.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip()
                            if name and target in name and not name.startswith("*."):
                                subdomains.add(name)
                    return list(subdomains)
        except Exception as e:
            print(f"CRT.sh query error: {e}")
        
        return []
    
    async def get_wayback_urls(self, target: str, limit: int = 1000) -> List[str]:
        """Get historical URLs from Wayback Machine"""
        if not self.session:
            return []
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx"
            params = {
                "url": f"*.{target}/*",
                "output": "url",
                "fl": "url",
                "limit": limit
            }
            
            async with self.session.get(url, params=params, timeout=60) as response:
                if response.status == 200:
                    text = await response.text()
                    urls = [line.strip() for line in text.split("\n") if line.strip()]
                    return urls
        except Exception as e:
            print(f"Wayback URLs error: {e}")
        
        return []
    
    async def fingerprint_technologies(self, subdomains: List[str]) -> List[Dict]:
        """Fingerprint technologies using httpx"""
        if not subdomains:
            return []
        
        # Write subdomains to file
        subdomains_file = f"{self.temp_dir}/tech_subdomains.txt"
        with open(subdomains_file, 'w') as f:
            for subdomain in subdomains:
                f.write(f"https://{subdomain}\n")
        
        output_file = f"{self.temp_dir}/tech_results.json"
        cmd = [
            "httpx",
            "-l", subdomains_file,
            "-tech-detect",
            "-json",
            "-o", output_file,
            "-silent",
            "-timeout", "10"
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        technologies = []
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        tech_info = {
                            "url": data.get("url"),
                            "status_code": data.get("status_code"),
                            "title": data.get("title"),
                            "technologies": data.get("technologies", []),
                            "webserver": data.get("webserver"),
                            "content_length": data.get("content_length", 0)
                        }
                        technologies.append(tech_info)
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(output_file)
        
        os.unlink(subdomains_file)
        return technologies

class ActiveReconTools(ToolExecutor):
    """Tools for Phase 2: Active Reconnaissance"""
    
    async def probe_live_hosts(self, urls: List[str]) -> List[Dict]:
        """Probe hosts with httpx to check if they're live"""
        if not urls:
            return []
        
        # Write URLs to file
        urls_file = f"{self.temp_dir}/probe_urls.txt"
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        output_file = f"{self.temp_dir}/probe_results.json"
        cmd = [
            "httpx",
            "-l", urls_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-timeout", "10",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server"
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        live_hosts = []
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        host_info = {
                            "url": data.get("url"),
                            "status_code": data.get("status_code"),
                            "title": data.get("title"),
                            "technologies": data.get("technologies", []),
                            "webserver": data.get("webserver"),
                            "content_length": data.get("content_length", 0),
                            "response_time": data.get("time")
                        }
                        live_hosts.append(host_info)
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(output_file)
        
        os.unlink(urls_file)
        return live_hosts
    
    async def scan_ports(self, hosts: List[str], top_ports: int = 1000) -> Dict[str, List[int]]:
        """Scan top ports with naabu"""
        if not hosts:
            return {}
        
        # Write hosts to file
        hosts_file = f"{self.temp_dir}/port_hosts.txt"
        with open(hosts_file, 'w') as f:
            for host in hosts:
                # Extract hostname from URL
                parsed = urlparse(host)
                hostname = parsed.netloc.split(':')[0]
                f.write(f"{hostname}\n")
        
        output_file = f"{self.temp_dir}/port_results.json"
        cmd = [
            "naabu",
            "-l", hosts_file,
            "-p", f"1-{top_ports}",
            "-json",
            "-o", output_file,
            "-silent",
            "-rate", "1000"
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        port_results = {}
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        host = data.get("host")
                        port = data.get("port")
                        
                        if host not in port_results:
                            port_results[host] = []
                        port_results[host].append(port)
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(output_file)
        
        os.unlink(hosts_file)
        return port_results
    
    async def resolve_dns(self, domains: List[str]) -> Dict[str, List[str]]:
        """Resolve DNS records with dnsx"""
        if not domains:
            return {}
        
        # Write domains to file
        domains_file = f"{self.temp_dir}/dns_domains.txt"
        with open(domains_file, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        output_file = f"{self.temp_dir}/dns_results.json"
        cmd = [
            "dnsx",
            "-l", domains_file,
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-txt",
            "-json",
            "-o", output_file,
            "-silent"
        ]
        
        returncode, stdout, stderr = await self.run_command(cmd)
        
        dns_results = {}
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        domain = data.get("domain")
                        record_type = data.get("type")
                        record_value = data.get("value")
                        
                        if domain not in dns_results:
                            dns_results[domain] = []
                        
                        dns_results[domain].append({
                            "type": record_type,
                            "value": record_value
                        })
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(output_file)
        
        os.unlink(domains_file)
        return dns_results

class AttackSurfaceTools(ToolExecutor):
    """Tools for Phase 3: Attack Surface Expansion"""
    
    async def brute_force_directories(self, base_urls: List[str], wordlist: str = None) -> List[Dict]:
        """Brute force directories with ffuf"""
        if not base_urls:
            return []
        
        # Use default wordlist if none provided
        if not wordlist:
            wordlist = "/usr/share/wordlists/common.txt"
        
        results = []
        
        for base_url in base_urls:
            output_file = f"{self.temp_dir}/ffuf_{hash(base_url)}.json"
            cmd = [
                "ffuf",
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist,
                "-o", output_file,
                "-of", "json",
                "-t", "50",
                "-timeout", "10",
                "-mc", "200,301,302,403",
                "-silent"
            ]
            
            returncode, stdout, stderr = await self.run_command(cmd, timeout=600)
            
            if returncode == 0 and os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for result in data.get("results", []):
                            results.append({
                                "url": result.get("url"),
                                "status_code": result.get("status"),
                                "length": result.get("length"),
                                "base_url": base_url
                            })
                except json.JSONDecodeError:
                    pass
                
                os.unlink(output_file)
        
        return results
    
    async def discover_parameters(self, urls: List[str]) -> List[Dict]:
        """Discover parameters with ParamSpider"""
        if not urls:
            return []
        
        results = []
        
        for url in urls:
            output_file = f"{self.temp_dir}/params_{hash(url)}.txt"
            cmd = [
                "paramspider",
                "-d", url,
                "-o", output_file,
                "-l", "high"
            ]
            
            returncode, stdout, stderr = await self.run_command(cmd)
            
            if returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        param_url = line.strip()
                        if param_url and "=" in param_url:
                            results.append({
                                "url": param_url,
                                "base_url": url,
                                "parameters": param_url.split("?")[1] if "?" in param_url else ""
                            })
                
                os.unlink(output_file)
        
        return results
    
    async def discover_apis(self, base_urls: List[str]) -> List[Dict]:
        """Discover API endpoints"""
        if not base_urls:
            return []
        
        api_patterns = [
            "/api/v1/", "/api/v2/", "/api/", "/graphql", "/swagger.json",
            "/swagger-ui/", "/openapi.json", "/docs.json", "/rest/"
        ]
        
        results = []
        
        if not self.session:
            return results
        
        for base_url in base_urls:
            for pattern in api_patterns:
                try:
                    api_url = urljoin(base_url, pattern)
                    async with self.session.get(api_url, timeout=10) as response:
                        if response.status in [200, 401, 403]:
                            content = await response.text()
                            
                            # Check if it's actually an API response
                            if any(keyword in content.lower() for keyword in ["api", "swagger", "openapi", "graphql"]):
                                results.append({
                                    "url": api_url,
                                    "status_code": response.status,
                                    "content_type": response.headers.get("content-type", ""),
                                    "base_url": base_url,
                                    "type": "api_endpoint"
                                })
                except:
                    continue
        
        return results

class VulnerabilityScanningTools(ToolExecutor):
    """Tools for Phase 4: Vulnerability Scanning"""
    
    async def run_nuclei(self, targets: List[str], templates: str = None) -> List[Vulnerability]:
        """Run nuclei for vulnerability scanning"""
        if not targets:
            return []
        
        # Write targets to file
        targets_file = f"{self.temp_dir}/nuclei_targets.txt"
        with open(targets_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        output_file = f"{self.temp_dir}/nuclei_results.json"
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-timeout", "10",
            "-rate-limit", "100"
        ]
        
        if templates:
            cmd.extend(["-t", templates])
        
        returncode, stdout, stderr = await self.run_command(cmd, timeout=1800)
        
        vulnerabilities = []
        if returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        
                        # Map severity
                        severity_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                            "info": Severity.INFO
                        }
                        
                        vuln = Vulnerability(
                            id=f"nuclei_{hash(data.get('info', {}).get('name', ''))}",
                            title=data.get("info", {}).get("name", "Unknown"),
                            severity=severity_map.get(data.get("info", {}).get("severity", "info").lower(), Severity.INFO),
                            cvss_score=None,
                            endpoint=data.get("matched-at", ""),
                            parameter=data.get("extracted-results", [None])[0],
                            vulnerability_type=data.get("info", {}).get("classification", {}).get("cve-id", "Unknown"),
                            poc=data.get("request", "") + "\n" + data.get("response", ""),
                            impact=data.get("info", {}).get("description", ""),
                            remediation=data.get("info", {}).get("remediation", ""),
                            references=data.get("info", {}).get("reference", []),
                            request_proof=data.get("request", ""),
                            response_proof=data.get("response", ""),
                            validated=False,
                            phase_detected="vulnerability_scanning"
                        )
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue
            
            os.unlink(output_file)
        
        os.unlink(targets_file)
        return vulnerabilities
    
    async def scan_xss(self, urls: List[str]) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities with dalfox"""
        if not urls:
            return []
        
        vulnerabilities = []
        
        for url in urls:
            output_file = f"{self.temp_dir}/dalfox_{hash(url)}.json"
            cmd = [
                "dalfox",
                "url", url,
                "-o", output_file,
                "-silence",
                "mass"
            ]
            
            returncode, stdout, stderr = await self.run_command(cmd, timeout=300)
            
            if returncode == 0 and os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        
                        for vuln_data in data.get("vulns", []):
                            vuln = Vulnerability(
                                id=f"dalfox_{hash(vuln_data.get('param', ''))}",
                                title="Cross-Site Scripting (XSS)",
                                severity=Severity.HIGH,
                                cvss_score=6.1,
                                endpoint=url,
                                parameter=vuln_data.get("param"),
                                vulnerability_type="xss",
                                poc=vuln_data.get("poc", ""),
                                impact="JavaScript execution in victim's browser",
                                remediation="Implement proper input validation and output encoding",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                                request_proof=vuln_data.get("request", ""),
                                response_proof=vuln_data.get("response", ""),
                                validated=False,
                                phase_detected="vulnerability_scanning"
                            )
                            vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    pass
                
                os.unlink(output_file)
        
        return vulnerabilities
    
    async def scan_sql_injection(self, urls: List[str]) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities"""
        if not urls:
            return []
        
        vulnerabilities = []
        
        for url in urls:
            # Basic SQL injection test with sqlmap
            output_file = f"{self.temp_dir}/sqlmap_{hash(url)}.txt"
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--level=1",
                "--risk=1",
                "--output-dir", self.temp_dir
            ]
            
            returncode, stdout, stderr = await self.run_command(cmd, timeout=600)
            
            # Parse sqlmap output (simplified)
            if "is vulnerable" in stdout.lower():
                vuln = Vulnerability(
                    id=f"sqlmap_{hash(url)}",
                    title="SQL Injection",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    endpoint=url,
                    parameter=None,  # sqlmap would identify this
                    vulnerability_type="sql injection",
                    poc=stdout,
                    impact="Complete database compromise possible",
                    remediation="Use parameterized queries and input validation",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    request_proof=None,
                    response_proof=stdout,
                    validated=False,
                    phase_detected="vulnerability_scanning"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def scan_cors(self, urls: List[str]) -> List[Vulnerability]:
        """Scan for CORS misconfigurations"""
        if not self.session or not urls:
            return []
        
        vulnerabilities = []
        
        for url in urls:
            try:
                # Test CORS with malicious origin
                headers = {"Origin": "https://evil.com"}
                async with self.session.options(url, headers=headers, timeout=10) as response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")
                    
                    # Check for overly permissive CORS
                    if acao == "*" and acac == "true":
                        vuln = Vulnerability(
                            id=f"cors_{hash(url)}",
                            title="CORS Misconfiguration with Credentials",
                            severity=Severity.MEDIUM,
                            cvss_score=4.3,
                            endpoint=url,
                            parameter=None,
                            vulnerability_type="cors misconfiguration",
                            poc=f"Origin: https://evil.com\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            impact="Cross-origin requests can access sensitive data with credentials",
                            remediation="Restrict CORS origins and avoid using credentials with wildcard origins",
                            references=["https://portswigger.net/web-security/cors"],
                            request_proof=str(headers),
                            response_proof=dict(response.headers),
                            validated=False,
                            phase_detected="vulnerability_scanning"
                        )
                        vulnerabilities.append(vuln)
                    
                    elif "evil.com" in acao:
                        vuln = Vulnerability(
                            id=f"cors_{hash(url)}",
                            title="CORS Misconfiguration - Arbitrary Origin",
                            severity=Severity.LOW,
                            cvss_score=3.7,
                            endpoint=url,
                            parameter=None,
                            vulnerability_type="cors misconfiguration",
                            poc=f"Origin: https://evil.com\nAccess-Control-Allow-Origin: {acao}",
                            impact="Cross-origin requests from untrusted domains are allowed",
                            remediation="Implement strict CORS origin validation",
                            references=["https://portswigger.net/web-security/cors"],
                            request_proof=str(headers),
                            response_proof=dict(response.headers),
                            validated=False,
                            phase_detected="vulnerability_scanning"
                        )
                        vulnerabilities.append(vuln)
            except:
                continue
        
        return vulnerabilities

class ReportingTools(ToolExecutor):
    """Tools for Phase 7: Reporting"""
    
    async def generate_pdf_report(self, scan_data: Dict) -> bytes:
        """Generate PDF report (placeholder implementation)"""
        # This would typically use a library like reportlab or weasyprint
        # For now, return a placeholder
        report_content = f"""
        4postle Vulnerability Report
        
        Target: {scan_data.get('target', 'N/A')}
        Scan ID: {scan_data.get('scan_id', 'N/A')}
        
        Total Vulnerabilities: {len(scan_data.get('vulnerabilities', []))}
        Critical: {len([v for v in scan_data.get('vulnerabilities', []) if v.get('severity') == 'critical'])}
        High: {len([v for v in scan_data.get('vulnerabilities', []) if v.get('severity') == 'high'])}
        Medium: {len([v for v in scan_data.get('vulnerabilities', []) if v.get('severity') == 'medium'])}
        Low: {len([v for v in scan_data.get('vulnerabilities', []) if v.get('severity') == 'low'])}
        """
        
        return report_content.encode('utf-8')
    
    async def generate_csv_report(self, scan_data: Dict) -> str:
        """Generate CSV report"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Title', 'Severity', 'CVSS Score', 'Endpoint', 'Parameter',
            'Vulnerability Type', 'Impact', 'Remediation'
        ])
        
        # Write vulnerabilities
        for vuln in scan_data.get('vulnerabilities', []):
            writer.writerow([
                vuln.get('title', ''),
                vuln.get('severity', ''),
                vuln.get('cvss_score', ''),
                vuln.get('endpoint', ''),
                vuln.get('parameter', ''),
                vuln.get('vulnerability_type', ''),
                vuln.get('impact', ''),
                vuln.get('remediation', '')
            ])
        
        return output.getvalue()

# Utility functions
def hash(string: str) -> str:
    """Generate hash for filenames"""
    import hashlib
    return hashlib.md5(string.encode()).hexdigest()[:8]
