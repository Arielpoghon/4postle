"""
4postle - Professional Vulnerability Scanner Engine
Core scanning orchestrator following 7-phase methodology
"""

import asyncio
import subprocess
import json
import re
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import yaml
from pathlib import Path

from app.core.tools import (
    PassiveReconTools, ActiveReconTools, AttackSurfaceTools,
    VulnerabilityScanningTools, ReportingTools
)
from app.core.validator import VulnerabilityValidator, CVSSCalculator

class ScanPhase(Enum):
    PASSIVE_RECON = "passive_reconnaissance"
    ACTIVE_RECON = "active_reconnaissance"
    ATTACK_SURFACE = "attack_surface_expansion"
    VULN_SCANNING = "vulnerability_scanning"
    VALIDATION = "vulnerability_validation"
    RISK_SCORING = "risk_scoring"
    REPORTING = "reporting"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    id: str
    title: str
    severity: Severity
    cvss_score: Optional[float]
    endpoint: str
    parameter: Optional[str]
    vulnerability_type: str
    poc: str
    impact: str
    remediation: str
    references: List[str]
    request_proof: Optional[str]
    response_proof: Optional[str]
    validated: bool = False
    phase_detected: str = ""

@dataclass
class Asset:
    url: str
    status_code: Optional[int]
    title: Optional[str]
    technology: List[str]
    ip_address: Optional[str]
    open_ports: List[int]
    headers: Dict[str, str]

@dataclass
class ScanProgress:
    current_phase: ScanPhase
    phase_progress: float
    total_progress: float
    tools_running: List[str]
    assets_discovered: int
    vulnerabilities_found: int
    current_task: str

class FourpostleScanner:
    def __init__(self, target: str, scope: Dict[str, Any]):
        self.target = target
        self.scope = scope
        self.assets: List[Asset] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.progress = ScanProgress(
            current_phase=ScanPhase.PASSIVE_RECON,
            phase_progress=0.0,
            total_progress=0.0,
            tools_running=[],
            assets_discovered=0,
            vulnerabilities_found=0,
            current_task="Initializing scanner"
        )
        self.scan_id = f"scan_{int(time.time())}"
        
    async def run_full_scan(self) -> Dict[str, Any]:
        """Execute complete 7-phase scanning methodology"""
        results = {
            "scan_id": self.scan_id,
            "target": self.target,
            "start_time": time.time(),
            "phases": {},
            "assets": [],
            "vulnerabilities": [],
            "summary": {}
        }
        
        try:
            # Phase 1: Passive Reconnaissance
            await self._update_progress(ScanPhase.PASSIVE_RECON, 0, "Starting passive reconnaissance")
            passive_results = await self._passive_reconnaissance()
            results["phases"]["passive_recon"] = passive_results
            await self._update_progress(ScanPhase.PASSIVE_RECON, 100, "Passive reconnaissance completed")
            
            # Phase 2: Active Reconnaissance
            await self._update_progress(ScanPhase.ACTIVE_RECON, 0, "Starting active reconnaissance")
            active_results = await self._active_reconnaissance()
            results["phases"]["active_recon"] = active_results
            await self._update_progress(ScanPhase.ACTIVE_RECON, 100, "Active reconnaissance completed")
            
            # Phase 3: Attack Surface Expansion
            await self._update_progress(ScanPhase.ATTACK_SURFACE, 0, "Expanding attack surface")
            attack_surface_results = await self._attack_surface_expansion()
            results["phases"]["attack_surface"] = attack_surface_results
            await self._update_progress(ScanPhase.ATTACK_SURFACE, 100, "Attack surface expansion completed")
            
            # Phase 4: Vulnerability Scanning
            await self._update_progress(ScanPhase.VULN_SCANNING, 0, "Starting vulnerability scanning")
            vuln_results = await self._vulnerability_scanning()
            results["phases"]["vulnerability_scanning"] = vuln_results
            await self._update_progress(ScanPhase.VULN_SCANNING, 100, "Vulnerability scanning completed")
            
            # Phase 5: Vulnerability Validation
            await self._update_progress(ScanPhase.VALIDATION, 0, "Validating vulnerabilities")
            validated_vulns = await self._vulnerability_validation()
            results["phases"]["validation"] = validated_vulns
            await self._update_progress(ScanPhase.VALIDATION, 100, "Vulnerability validation completed")
            
            # Phase 6: Risk Scoring
            await self._update_progress(ScanPhase.RISK_SCORING, 0, "Scoring and prioritizing")
            risk_results = await self._risk_scoring()
            results["phases"]["risk_scoring"] = risk_results
            await self._update_progress(ScanPhase.RISK_SCORING, 100, "Risk scoring completed")
            
            # Phase 7: Reporting
            await self._update_progress(ScanPhase.REPORTING, 0, "Generating reports")
            reports = await self._generate_reports()
            results["phases"]["reporting"] = reports
            await self._update_progress(ScanPhase.REPORTING, 100, "Reports generated")
            
            # Final results
            results["assets"] = [asdict(asset) for asset in self.assets]
            results["vulnerabilities"] = [asdict(vuln) for vuln in self.vulnerabilities if vuln.validated]
            results["summary"] = self._generate_summary()
            results["end_time"] = time.time()
            
        except Exception as e:
            results["error"] = str(e)
            results["end_time"] = time.time()
            
        return results
    
    async def _passive_reconnaissance(self) -> Dict[str, Any]:
        """Phase 1: Passive Reconnaissance - NO target interaction"""
        results = {
            "subdomains": [],
            "ip_ranges": [],
            "technologies": [],
            "historical_urls": [],
            "dns_records": {},
            "certificates": []
        }
        
        tools = ["subfinder", "amass", "crtsh", "waybackurls", "httpx-tech"]
        self.progress.tools_running = tools
        
        async with PassiveReconTools() as passive_tools:
            # Subdomain discovery
            await self._update_progress(ScanPhase.PASSIVE_RECON, 10, "Discovering subdomains with subfinder")
            subdomains = await passive_tools.run_subfinder(self.target)
            results["subdomains"].extend(subdomains)
            
            await self._update_progress(ScanPhase.PASSIVE_RECON, 30, "Discovering subdomains with amass")
            amass_results = await passive_tools.run_amass(self.target)
            results["subdomains"].extend(amass_results)
            
            # Certificate Transparency
            await self._update_progress(ScanPhase.PASSIVE_RECON, 50, "Querying certificate transparency")
            cert_results = await passive_tools.query_crtsh(self.target)
            results["certificates"].extend(cert_results)
            
            # Historical URLs
            await self._update_progress(ScanPhase.PASSIVE_RECON, 70, "Extracting historical URLs")
            historical = await passive_tools.get_wayback_urls(self.target)
            results["historical_urls"].extend(historical)
            
            # Technology fingerprinting
            await self._update_progress(ScanPhase.PASSIVE_RECON, 90, "Fingerprinting technologies")
            tech_results = await passive_tools.fingerprint_technologies(list(set(results["subdomains"])))
            results["technologies"].extend(tech_results)
        
        # Store discovered assets
        for subdomain in set(results["subdomains"]):
            asset = Asset(
                url=f"https://{subdomain}",
                status_code=None,
                title=None,
                technology=[],
                ip_address=None,
                open_ports=[],
                headers={}
            )
            self.assets.append(asset)
        
        return results
    
    async def _active_reconnaissance(self) -> Dict[str, Any]:
        """Phase 2: Active Reconnaissance - LOW noise, controlled"""
        results = {
            "live_hosts": [],
            "open_ports": {},
            "web_services": [],
            "security_headers": {},
            "cdn_waf": {}
        }
        
        tools = ["httpx", "naabu", "dnsx", "whatweb"]
        self.progress.tools_running = tools
        
        async with ActiveReconTools() as active_tools:
            # Check live hosts
            await self._update_progress(ScanPhase.ACTIVE_RECON, 20, "Probing live hosts")
            urls = [asset.url for asset in self.assets]
            live_hosts = await active_tools.probe_live_hosts(urls)
            results["live_hosts"] = live_hosts
            
            # Update asset information
            for host_info in live_hosts:
                for asset in self.assets:
                    if asset.url == host_info["url"]:
                        asset.status_code = host_info["status_code"]
                        asset.title = host_info["title"]
                        asset.technology = host_info["technologies"]
                        break
            
            # Port scanning
            await self._update_progress(ScanPhase.ACTIVE_RECON, 50, "Scanning top ports")
            hosts = [host_info["url"] for host_info in live_hosts if host_info["status_code"] == 200]
            port_results = await active_tools.scan_ports(hosts)
            results["open_ports"] = port_results
            
            # DNS resolution
            await self._update_progress(ScanPhase.ACTIVE_RECON, 80, "Resolving DNS records")
            subdomains = [asset.url.replace("https://", "").replace("http://", "") for asset in self.assets]
            dns_results = await active_tools.resolve_dns(subdomains)
            results["dns_records"] = dns_results
        
        return results
    
    async def _attack_surface_expansion(self) -> Dict[str, Any]:
        """Phase 3: Attack Surface Expansion"""
        results = {
            "directories": [],
            "parameters": [],
            "apis": [],
            "admin_panels": [],
            "backup_files": []
        }
        
        tools = ["ffuf", "paramspider", "arjun", "linkfinder"]
        self.progress.tools_running = tools
        
        async with AttackSurfaceTools() as attack_tools:
            # Directory brute-forcing
            await self._update_progress(ScanPhase.ATTACK_SURFACE, 25, "Brute-forcing directories")
            live_urls = [asset.url for asset in self.assets if asset.status_code == 200]
            directories = await attack_tools.brute_force_directories(live_urls)
            results["directories"] = directories
            
            # Parameter discovery
            await self._update_progress(ScanPhase.ATTACK_SURFACE, 50, "Discovering parameters")
            parameters = await attack_tools.discover_parameters(live_urls)
            results["parameters"] = parameters
            
            # API discovery
            await self._update_progress(ScanPhase.ATTACK_SURFACE, 75, "Finding APIs")
            apis = await attack_tools.discover_apis(live_urls)
            results["apis"] = apis
        
        return results
    
    async def _vulnerability_scanning(self) -> Dict[str, Any]:
        """Phase 4: Intelligent Vulnerability Scanning"""
        results = {
            "vulnerabilities": [],
            "tools_used": [],
            "scan_coverage": {}
        }
        
        tools = ["nuclei", "dalfox", "sqlmap", "crlfuzz", "corscanner"]
        self.progress.tools_running = tools
        
        async with VulnerabilityScanningTools() as vuln_tools:
            # Nuclei scanning
            await self._update_progress(ScanPhase.VULN_SCANNING, 20, "Running nuclei templates")
            live_urls = [asset.url for asset in self.assets if asset.status_code == 200]
            nuclei_results = await vuln_tools.run_nuclei(live_urls)
            self.vulnerabilities.extend(nuclei_results)
            
            # XSS scanning
            await self._update_progress(ScanPhase.VULN_SCANNING, 40, "Scanning for XSS")
            xss_results = await vuln_tools.scan_xss(live_urls)
            self.vulnerabilities.extend(xss_results)
            
            # SQL injection scanning
            await self._update_progress(ScanPhase.VULN_SCANNING, 60, "Scanning for SQL injection")
            sqli_results = await vuln_tools.scan_sql_injection(live_urls)
            self.vulnerabilities.extend(sqli_results)
            
            # CORS misconfigurations
            await self._update_progress(ScanPhase.VULN_SCANNING, 80, "Checking CORS misconfigurations")
            cors_results = await vuln_tools.scan_cors(live_urls)
            self.vulnerabilities.extend(cors_results)
        
        results["vulnerabilities"] = [asdict(vuln) for vuln in self.vulnerabilities]
        return results
    
    async def _vulnerability_validation(self) -> Dict[str, Any]:
        """Phase 5: Vulnerability Validation - CRITICAL"""
        validated = []
        
        await self._update_progress(ScanPhase.VALIDATION, 25, "Validating vulnerabilities")
        
        async with VulnerabilityValidator() as validator:
            for i, vuln in enumerate(self.vulnerabilities):
                if await validator.validate_vulnerability(vuln):
                    vuln.validated = True
                    validated.append(asdict(vuln))
                
                await self._update_progress(
                    ScanPhase.VALIDATION, 
                    25 + (75 * len(validated) / len(self.vulnerabilities)),
                    f"Validated {len(validated)}/{len(self.vulnerabilities)} vulnerabilities"
                )
        
        return {"validated_vulnerabilities": validated}
    
    async def _risk_scoring(self) -> Dict[str, Any]:
        """Phase 6: Risk Scoring & Prioritization"""
        scored_vulns = []
        
        await self._update_progress(ScanPhase.RISK_SCORING, 50, "Scoring vulnerabilities")
        
        for vuln in self.vulnerabilities:
            if vuln.validated:
                score = CVSSCalculator.calculate_cvss_score(vuln)
                vuln.cvss_score = score
                scored_vulns.append(asdict(vuln))
        
        # Sort by CVSS score
        scored_vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        return {"scored_vulnerabilities": scored_vulns}
    
    async def _generate_reports(self) -> Dict[str, Any]:
        """Phase 7: Reporting Engine"""
        await self._update_progress(ScanPhase.REPORTING, 50, "Generating reports")
        
        scan_data = {
            "scan_id": self.scan_id,
            "target": self.target,
            "vulnerabilities": [asdict(vuln) for vuln in self.vulnerabilities if vuln.validated],
            "assets": [asdict(asset) for asset in self.assets],
            "summary": self._generate_summary()
        }
        
        async with ReportingTools() as reporting_tools:
            reports = {
                "json": scan_data,
                "markdown": await self._generate_markdown_report(),
                "pdf": await reporting_tools.generate_pdf_report(scan_data),
                "csv": await reporting_tools.generate_csv_report(scan_data),
                "summary": self._generate_summary()
            }
        
        return reports
    
    async def _update_progress(self, phase: ScanPhase, phase_progress: float, task: str):
        """Update scan progress for frontend"""
        phase_weights = {
            ScanPhase.PASSIVE_RECON: 10,
            ScanPhase.ACTIVE_RECON: 20,
            ScanPhase.ATTACK_SURFACE: 15,
            ScanPhase.VULN_SCANNING: 30,
            ScanPhase.VALIDATION: 15,
            ScanPhase.RISK_SCORING: 5,
            ScanPhase.REPORTING: 5
        }
        
        total_weight = sum(phase_weights.values())
        completed_weight = sum(phase_weights[p] for p in list(ScanPhase) if phase_weights[p] < phase_weights[phase])
        current_weight = phase_weights[phase] * (phase_progress / 100)
        
        self.progress.current_phase = phase
        self.progress.phase_progress = phase_progress
        self.progress.total_progress = ((completed_weight + current_weight) / total_weight) * 100
        self.progress.current_task = task
        self.progress.assets_discovered = len(self.assets)
        self.progress.vulnerabilities_found = len([v for v in self.vulnerabilities if v.validated])
    
    # Helper methods
    def _generate_summary(self) -> Dict:
        """Generate scan summary"""
        vuln_counts = {
            "critical": len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL and v.validated]),
            "high": len([v for v in self.vulnerabilities if v.severity == Severity.HIGH and v.validated]),
            "medium": len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM and v.validated]),
            "low": len([v for v in self.vulnerabilities if v.severity == Severity.LOW and v.validated])
        }
        
        return {
            "total_assets": len(self.assets),
            "total_vulnerabilities": sum(vuln_counts.values()),
            "severity_breakdown": vuln_counts,
            "scan_duration": time.time() - float(self.scan_id.split("_")[1]) if "_" in self.scan_id else 0
        }
