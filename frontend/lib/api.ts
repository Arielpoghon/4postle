/**
 * 4postle API Service
 * Connects frontend with backend vulnerability scanner
 */

export interface ScanRequest {
  target: string;
  scope?: {
    in_scope?: string[];
    out_of_scope?: string[];
    max_depth?: number;
  };
  options?: {
    passive_only?: boolean;
    aggressive_mode?: boolean;
    timeout?: number;
  };
}

export interface ScanResponse {
  scan_id: string;
  target: string;
  status: 'running' | 'completed' | 'error';
  created_at: string;
  phases_completed: number;
  total_phases: number;
}

export interface ScanStatus {
  scan_id: string;
  target: string;
  status: 'running' | 'completed' | 'error';
  current_phase: string;
  progress: number;
  assets_discovered: number;
  vulnerabilities_found: number;
  current_task: string;
  tools_running: string[];
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score?: number;
  endpoint: string;
  parameter?: string;
  vulnerability_type: string;
  poc: string;
  impact: string;
  remediation: string;
  references: string[];
  validated: boolean;
  phase_detected: string;
}

export interface Asset {
  url: string;
  status_code?: number;
  title?: string;
  technology: string[];
  ip_address?: string;
  open_ports: number[];
  headers: Record<string, string>;
}

export interface ScanResults {
  scan_id: string;
  target: string;
  start_time: number;
  end_time: number;
  phases: Record<string, any>;
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  summary: {
    total_assets: number;
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
    scan_duration: number;
  };
}

export interface WebSocketProgress {
  scan_id: string;
  phase: string;
  phase_progress: number;
  total_progress: number;
  current_task: string;
  assets_discovered: number;
  vulnerabilities_found: number;
  tools_running: string[];
}

class APIService {
  private baseURL: string;
  private wsURL: string;

  constructor() {
    // In development, use localhost
    this.baseURL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    this.wsURL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';
  }

  /**
   * Create a new vulnerability scan
   */
  async createScan(request: ScanRequest): Promise<ScanResponse> {
    const response = await fetch(`${this.baseURL}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new Error(`Failed to create scan: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanId: string): Promise<ScanStatus> {
    const response = await fetch(`${this.baseURL}/api/v1/scans/${scanId}`);

    if (!response.ok) {
      throw new Error(`Failed to get scan status: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get detailed scan results
   */
  async getScanResults(scanId: string): Promise<ScanResults> {
    const response = await fetch(`${this.baseURL}/api/v1/scans/${scanId}/results`);

    if (!response.ok) {
      throw new Error(`Failed to get scan results: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get vulnerabilities for a scan
   */
  async getVulnerabilities(scanId: string, severity?: string): Promise<{ vulnerabilities: Vulnerability[]; total: number }> {
    const url = new URL(`${this.baseURL}/api/v1/scans/${scanId}/vulnerabilities`);
    if (severity) {
      url.searchParams.append('severity', severity);
    }

    const response = await fetch(url.toString());

    if (!response.ok) {
      throw new Error(`Failed to get vulnerabilities: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get assets discovered during scan
   */
  async getAssets(scanId: string): Promise<{ assets: Asset[]; total: number }> {
    const response = await fetch(`${this.baseURL}/api/v1/scans/${scanId}/assets`);

    if (!response.ok) {
      throw new Error(`Failed to get assets: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Get scan report in specified format
   */
  async getScanReport(scanId: string, format: 'json' | 'markdown' | 'summary' = 'json'): Promise<any> {
    const response = await fetch(`${this.baseURL}/api/v1/scans/${scanId}/report?format=${format}`);

    if (!response.ok) {
      throw new Error(`Failed to get scan report: ${response.statusText}`);
    }

    if (format === 'markdown' || format === 'summary') {
      return response.json();
    }

    return response.json();
  }

  /**
   * List all scans
   */
  async listScans(): Promise<{ scans: ScanStatus[]; total: number }> {
    const response = await fetch(`${this.baseURL}/api/v1/scans`);

    if (!response.ok) {
      throw new Error(`Failed to list scans: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Delete a scan
   */
  async deleteScan(scanId: string): Promise<void> {
    const response = await fetch(`${this.baseURL}/api/v1/scans/${scanId}`, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error(`Failed to delete scan: ${response.statusText}`);
    }
  }

  /**
   * Create WebSocket connection for real-time updates
   */
  createWebSocket(scanId: string): WebSocket {
    const wsUrl = `${this.wsURL}/api/v1/ws/scans/${scanId}`;
    return new WebSocket(wsUrl);
  }

  /**
   * Helper method to format scan phases for display
   */
  formatPhase(phase: string): string {
    const phaseMap: Record<string, string> = {
      'passive_reconnaissance': 'Passive Reconnaissance',
      'active_reconnaissance': 'Active Reconnaissance',
      'attack_surface_expansion': 'Attack Surface Expansion',
      'vulnerability_scanning': 'Vulnerability Scanning',
      'vulnerability_validation': 'Vulnerability Validation',
      'risk_scoring': 'Risk Scoring',
      'reporting': 'Reporting',
      'completed': 'Completed',
      'error': 'Error'
    };

    return phaseMap[phase] || phase;
  }

  /**
   * Helper method to format severity for display
   */
  formatSeverity(severity: string): string {
    return severity.charAt(0).toUpperCase() + severity.slice(1);
  }

  /**
   * Helper method to get severity color
   */
  getSeverityColor(severity: string): string {
    const colorMap: Record<string, string> = {
      'critical': '#ef4444',
      'high': '#f97316',
      'medium': '#eab308',
      'low': '#84cc16',
      'info': '#22c55e'
    };

    return colorMap[severity] || '#6b7280';
  }

  /**
   * Helper method to validate target input
   */
  validateTarget(target: string): { valid: boolean; error?: string } {
    if (!target || target.trim() === '') {
      return { valid: false, error: 'Target is required' };
    }

    const trimmed = target.trim();
    
    // Basic URL validation
    try {
      new URL(trimmed);
      return { valid: true };
    } catch {
      // Check if it's a domain or IP
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      
      if (domainRegex.test(trimmed) || ipRegex.test(trimmed)) {
        return { valid: true };
      }
      
      return { valid: false, error: 'Invalid target format. Use domain, IP, or full URL' };
    }
  }

  /**
   * Helper method to format scan duration
   */
  formatDuration(seconds: number): string {
    if (seconds < 60) {
      return `${seconds}s`;
    } else if (seconds < 3600) {
      return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    } else {
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      return `${hours}h ${minutes}m`;
    }
  }

  /**
   * Helper method to format CVSS score with color
   */
  getCVSSColor(score: number): string {
    if (score >= 9.0) return '#ef4444'; // Critical
    if (score >= 7.0) return '#f97316'; // High
    if (score >= 4.0) return '#eab308'; // Medium
    if (score > 0.0) return '#84cc16'; // Low
    return '#22c55e'; // Info
  }

  /**
   * Helper method to group vulnerabilities by severity
   */
  groupVulnerabilitiesBySeverity(vulnerabilities: Vulnerability[]): Record<string, Vulnerability[]> {
    return vulnerabilities.reduce((groups, vuln) => {
      const severity = vuln.severity;
      if (!groups[severity]) {
        groups[severity] = [];
      }
      groups[severity].push(vuln);
      return groups;
    }, {} as Record<string, Vulnerability[]>);
  }

  /**
   * Helper method to count vulnerabilities by severity
   */
  countVulnerabilitiesBySeverity(vulnerabilities: Vulnerability[]): Record<string, number> {
    return vulnerabilities.reduce((counts, vuln) => {
      counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
      return counts;
    }, {} as Record<string, number>);
  }
}

// Export singleton instance
export const apiService = new APIService();
