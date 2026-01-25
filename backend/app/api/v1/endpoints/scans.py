"""
4postle Scan API Endpoints
REST API and WebSocket endpoints for vulnerability scanning
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from app.core.scanner import FourpostleScanner, ScanPhase, Severity
from app.core.config import settings
from app.models.scan import ScanCreate, ScanResponse, ScanStatus
from app.db.session import get_db

router = APIRouter()
logger = logging.getLogger(__name__)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_connections: Dict[str, List[str]] = {}
    
    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self.active_connections[scan_id] = websocket
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = []
        self.scan_connections[scan_id].append(scan_id)
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
        if scan_id in self.scan_connections:
            del self.scan_connections[scan_id]
    
    async def send_personal_message(self, message: str, scan_id: str):
        if scan_id in self.active_connections:
            websocket = self.active_connections[scan_id]
            try:
                await websocket.send_text(message)
            except:
                self.disconnect(scan_id)
    
    async def broadcast_to_scan(self, message: str, scan_id: str):
        if scan_id in self.scan_connections:
            for connection_id in self.scan_connections[scan_id]:
                await self.send_personal_message(message, connection_id)

manager = ConnectionManager()

# Active scans storage
active_scans: Dict[str, FourpostleScanner] = {}
scan_results: Dict[str, Dict] = {}

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP to scan")
    scope: Optional[Dict[str, Any]] = Field(default={}, description="Scan scope configuration")
    options: Optional[Dict[str, Any]] = Field(default={}, description="Scan options")
    
    class Config:
        schema_extra = {
            "example": {
                "target": "example.com",
                "scope": {
                    "in_scope": ["*.example.com"],
                    "out_of_scope": ["admin.example.com"],
                    "max_depth": 3
                },
                "options": {
                    "passive_only": False,
                    "aggressive_mode": False,
                    "timeout": 3600
                }
            }
        }

class ScanProgressUpdate(BaseModel):
    scan_id: str
    phase: str
    phase_progress: float
    total_progress: float
    current_task: str
    assets_discovered: int
    vulnerabilities_found: int
    tools_running: List[str]

@router.post("/scans", response_model=ScanResponse)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Create a new vulnerability scan
    
    Initiates a comprehensive 7-phase vulnerability scan:
    1. Passive Reconnaissance
    2. Active Reconnaissance  
    3. Attack Surface Expansion
    4. Vulnerability Scanning
    5. Vulnerability Validation
    6. Risk Scoring
    7. Reporting
    """
    try:
        # Validate target
        if not scan_request.target:
            raise HTTPException(status_code=400, detail="Target is required")
        
        # Generate scan ID
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        # Initialize scanner
        scanner = FourpostleScanner(
            target=scan_request.target,
            scope=scan_request.scope or {}
        )
        scanner.scan_id = scan_id
        
        # Store scanner
        active_scans[scan_id] = scanner
        
        # Start scan in background
        background_tasks.add_task(run_scan_background, scan_id, scanner)
        
        return ScanResponse(
            scan_id=scan_id,
            target=scan_request.target,
            status="running",
            created_at=datetime.utcnow(),
            phases_completed=0,
            total_phases=7
        )
        
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get current status of a scan"""
    if scan_id not in active_scans and scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_id in active_scans:
        scanner = active_scans[scan_id]
        return ScanStatus(
            scan_id=scan_id,
            target=scanner.target,
            status="running",
            current_phase=scanner.progress.current_phase.value,
            progress=scanner.progress.total_progress,
            assets_discovered=scanner.progress.assets_discovered,
            vulnerabilities_found=scanner.progress.vulnerabilities_found,
            current_task=scanner.progress.current_task,
            tools_running=scanner.progress.tools_running
        )
    else:
        # Scan completed
        result = scan_results[scan_id]
        return ScanStatus(
            scan_id=scan_id,
            target=result["target"],
            status="completed",
            current_phase="completed",
            progress=100.0,
            assets_discovered=len(result.get("assets", [])),
            vulnerabilities_found=len(result.get("vulnerabilities", [])),
            current_task="Scan completed",
            tools_running=[]
        )

@router.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get detailed scan results"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return scan_results[scan_id]

@router.get("/scans/{scan_id}/vulnerabilities")
async def get_vulnerabilities(scan_id: str, severity: Optional[str] = None):
    """Get vulnerabilities with optional severity filter"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    vulnerabilities = scan_results[scan_id].get("vulnerabilities", [])
    
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity]
    
    return {
        "scan_id": scan_id,
        "vulnerabilities": vulnerabilities,
        "total": len(vulnerabilities)
    }

@router.get("/scans/{scan_id}/assets")
async def get_assets(scan_id: str):
    """Get discovered assets"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    assets = scan_results[scan_id].get("assets", [])
    
    return {
        "scan_id": scan_id,
        "assets": assets,
        "total": len(assets)
    }

@router.get("/scans/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "json"):
    """Get scan report in specified format"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    results = scan_results[scan_id]
    
    if format == "json":
        return results
    elif format == "markdown":
        # Generate markdown report
        report = generate_markdown_report(results)
        return JSONResponse(content={"report": report, "format": "markdown"})
    elif format == "summary":
        return results.get("summary", {})
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use: json, markdown, summary")

@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan and results"""
    if scan_id in active_scans:
        del active_scans[scan_id]
    if scan_id in scan_results:
        del scan_results[scan_id]
    
    manager.disconnect(scan_id)
    
    return {"message": f"Scan {scan_id} deleted successfully"}

@router.get("/scans")
async def list_scans():
    """List all scans"""
    scans = []
    
    # Active scans
    for scan_id, scanner in active_scans.items():
        scans.append({
            "scan_id": scan_id,
            "target": scanner.target,
            "status": "running",
            "progress": scanner.progress.total_progress,
            "current_phase": scanner.progress.current_phase.value,
            "assets_discovered": scanner.progress.assets_discovered,
            "vulnerabilities_found": scanner.progress.vulnerabilities_found
        })
    
    # Completed scans
    for scan_id, results in scan_results.items():
        scans.append({
            "scan_id": scan_id,
            "target": results["target"],
            "status": "completed",
            "progress": 100.0,
            "current_phase": "completed",
            "assets_discovered": len(results.get("assets", [])),
            "vulnerabilities_found": len(results.get("vulnerabilities", []))
        })
    
    return {"scans": scans, "total": len(scans)}

@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    
    Provides live updates during scan execution:
    - Phase progress
    - Current tools running
    - Assets discovered
    - Vulnerabilities found
    - Current task/status
    """
    await manager.connect(websocket, scan_id)
    
    try:
        while True:
            # Send current progress if scan is active
            if scan_id in active_scans:
                scanner = active_scans[scan_id]
                progress_update = ScanProgressUpdate(
                    scan_id=scan_id,
                    phase=scanner.progress.current_phase.value,
                    phase_progress=scanner.progress.phase_progress,
                    total_progress=scanner.progress.total_progress,
                    current_task=scanner.progress.current_task,
                    assets_discovered=scanner.progress.assets_discovered,
                    vulnerabilities_found=scanner.progress.vulnerabilities_found,
                    tools_running=scanner.progress.tools_running
                )
                
                await websocket.send_text(json.dumps(progress_update.dict()))
            
            # Wait before next update
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        manager.disconnect(scan_id)
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        manager.disconnect(scan_id)

async def run_scan_background(scan_id: str, scanner: FourpostleScanner):
    """Run scan in background and update progress"""
    try:
        # Custom progress callback
        async def update_progress_callback():
            if scan_id in manager.active_connections:
                progress_update = ScanProgressUpdate(
                    scan_id=scan_id,
                    phase=scanner.progress.current_phase.value,
                    phase_progress=scanner.progress.phase_progress,
                    total_progress=scanner.progress.total_progress,
                    current_task=scanner.progress.current_task,
                    assets_discovered=scanner.progress.assets_discovered,
                    vulnerabilities_found=scanner.progress.vulnerabilities_found,
                    tools_running=scanner.progress.tools_running
                )
                await manager.send_personal_message(
                    json.dumps(progress_update.dict()), 
                    scan_id
                )
        
        # Override the update_progress method to send WebSocket updates
        original_update = scanner._update_progress
        async def websocket_update_progress(phase, phase_progress, task):
            await original_update(phase, phase_progress, task)
            await update_progress_callback()
        
        scanner._update_progress = websocket_update_progress
        
        # Run the scan
        results = await scanner.run_full_scan()
        
        # Store results
        scan_results[scan_id] = results
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        # Send completion message
        completion_update = ScanProgressUpdate(
            scan_id=scan_id,
            phase="completed",
            phase_progress=100.0,
            total_progress=100.0,
            current_task="Scan completed successfully",
            assets_discovered=len(results.get("assets", [])),
            vulnerabilities_found=len(results.get("vulnerabilities", [])),
            tools_running=[]
        )
        
        await manager.send_personal_message(
            json.dumps(completion_update.dict()),
            scan_id
        )
        
    except Exception as e:
        logger.error(f"Background scan error for {scan_id}: {e}")
        
        # Send error message
        error_update = ScanProgressUpdate(
            scan_id=scan_id,
            phase="error",
            phase_progress=0.0,
            total_progress=0.0,
            current_task=f"Scan failed: {str(e)}",
            assets_discovered=0,
            vulnerabilities_found=0,
            tools_running=[]
        )
        
        await manager.send_personal_message(
            json.dumps(error_update.dict()),
            scan_id
        )
        
        # Clean up
        if scan_id in active_scans:
            del active_scans[scan_id]

def generate_markdown_report(results: Dict) -> str:
    """Generate markdown report from scan results"""
    report = f"""# 4postle Vulnerability Assessment Report

**Target:** {results.get('target', 'N/A')}  
**Scan ID:** {results.get('scan_id', 'N/A')}  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

- **Total Assets Discovered:** {len(results.get('assets', []))}
- **Total Vulnerabilities:** {len(results.get('vulnerabilities', []))}
- **Critical:** {len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'critical'])}
- **High:** {len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'high'])}
- **Medium:** {len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'medium'])}
- **Low:** {len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'low'])}

## Vulnerabilities

"""
    
    vulnerabilities = results.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        report += f"""### {vuln.get('title', 'N/A')}

**Severity:** {vuln.get('severity', 'N/A').upper()}  
**CVSS Score:** {vuln.get('cvss_score', 'N/A')}  
**Endpoint:** {vuln.get('endpoint', 'N/A')}  
**Type:** {vuln.get('vulnerability_type', 'N/A')}

**Impact:** {vuln.get('impact', 'N/A')}

**Proof of Concept:** {vuln.get('poc', 'N/A')}

**Remediation:** {vuln.get('remediation', 'N/A')}

---

"""
    
    report += f"""
## Discovered Assets

Total {len(results.get('assets', []))} assets discovered:

"""
    
    for asset in results.get('assets', [])[:20]:  # Limit to first 20
        report += f"- {asset.get('url', 'N/A')} (Status: {asset.get('status_code', 'N/A')})\n"
    
    if len(results.get('assets', [])) > 20:
        report += f"... and {len(results.get('assets', [])) - 20} more assets\n"
    
    report += """
## Recommendations

1. **Immediate Action Required:** Address all Critical and High severity vulnerabilities
2. **Short-term:** Plan remediation for Medium severity findings
3. **Long-term:** Implement security best practices for Low severity issues
4. **Continuous Monitoring:** Regular scanning to detect new vulnerabilities

---
*Report generated by 4postle - Professional Vulnerability Scanner*
"""
    
    return report
