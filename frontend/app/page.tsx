'use client';

import { useState, useEffect, useMemo } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, XCircle, Clock, Target, Lock, Bug, Globe, Ban, Play, Settings, Terminal } from 'lucide-react';

interface Vulnerability {
  id: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  count: number;
}

interface ScanStatus {
  state: 'idle' | 'scanning' | 'finished' | 'error';
  progress: number;
  logs: string[];
}

interface TargetScope {
  target: string;
  inScope: string[];
  outOfScope: string[];
}

export default function Home() {
  const [scanStatus, setScanStatus] = useState<ScanStatus>({
    state: 'idle',
    progress: 0,
    logs: []
  });

  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([
    { id: '1', severity: 'critical', title: 'SQL Injection', description: 'Critical SQL injection vulnerability found', count: 3 },
    { id: '2', severity: 'high', title: 'XSS Vulnerability', description: 'Cross-site scripting vulnerability', count: 5 },
    { id: '3', severity: 'medium', title: 'CSRF Token Missing', description: 'Cross-site request forgery protection missing', count: 2 },
    { id: '4', severity: 'low', title: 'Information Disclosure', description: 'Sensitive information exposed', count: 8 },
    { id: '5', severity: 'informational', title: 'Missing Security Headers', description: 'Security headers not configured', count: 4 }
  ]);

  const [targetScope, setTargetScope] = useState<TargetScope>({
    target: '',
    inScope: [],
    outOfScope: []
  });

  const [isScanning, setIsScanning] = useState(false);
  const [showResults, setShowResults] = useState(false);

  const startScan = () => {
    if (!targetScope.target.trim()) {
      alert('Please enter a target URL or IP address');
      return;
    }

    setIsScanning(true);
    setShowResults(false);
    setScanStatus({ 
      state: 'scanning', 
      progress: 0, 
      logs: [
        `[${new Date().toLocaleTimeString()}] Initializing scan...`,
        `[${new Date().toLocaleTimeString()}] Target: ${targetScope.target}`,
        `[${new Date().toLocaleTimeString()}] Starting vulnerability assessment...`
      ] 
    });
    
    const interval = setInterval(() => {
      setScanStatus(prev => {
        const newProgress = Math.min(prev.progress + Math.random() * 15, 100);
        const newLogs = [...prev.logs, `[${new Date().toLocaleTimeString()}] Scanning... ${Math.floor(newProgress)}%`];
        
        if (newProgress >= 100) {
          clearInterval(interval);
          setIsScanning(false);
          setShowResults(true);
          return { 
            state: 'finished', 
            progress: 100, 
            logs: [...newLogs, `[${new Date().toLocaleTimeString()}] Scan completed successfully!`, `[${new Date().toLocaleTimeString()}] Found ${totalVulnerabilities} vulnerabilities`] 
          };
        }
        
        return { ...prev, progress: newProgress, logs: newLogs };
      });
    }, 500);
  };

  const addInScopeRule = () => {
    setTargetScope(prev => ({
      ...prev,
      inScope: [...prev.inScope, '']
    }));
  };

  const addOutOfScopeRule = () => {
    setTargetScope(prev => ({
      ...prev,
      outOfScope: [...prev.outOfScope, '']
    }));
  };

  const updateInScopeRule = (index: number, value: string) => {
    setTargetScope(prev => ({
      ...prev,
      inScope: prev.inScope.map((rule, i) => i === index ? value : rule)
    }));
  };

  const updateOutOfScopeRule = (index: number, value: string) => {
    setTargetScope(prev => ({
      ...prev,
      outOfScope: prev.outOfScope.map((rule, i) => i === index ? value : rule)
    }));
  };

  const removeInScopeRule = (index: number) => {
    setTargetScope(prev => ({
      ...prev,
      inScope: prev.inScope.filter((_, i) => i !== index)
    }));
  };

  const removeOutOfScopeRule = (index: number) => {
    setTargetScope(prev => ({
      ...prev,
      outOfScope: prev.outOfScope.filter((_, i) => i !== index)
    }));
  };

  const getStatusIcon = () => {
    switch (scanStatus.state) {
      case 'idle':
        return <Clock className="w-6 h-6 text-gray-500" />;
      case 'scanning':
        return <Activity className="w-6 h-6 text-green-400 animate-pulse" />;
      case 'finished':
        return <CheckCircle className="w-6 h-6 text-green-400" />;
      case 'error':
        return <XCircle className="w-6 h-6 text-red-400" />;
      default:
        return <Clock className="w-6 h-6 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 border-red-400';
      case 'high':
        return 'text-orange-400 border-orange-400';
      case 'medium':
        return 'text-yellow-400 border-yellow-400';
      case 'low':
        return 'text-lime-400 border-lime-400';
      case 'informational':
        return 'text-green-400 border-green-400';
      default:
        return 'text-gray-400 border-gray-400';
    }
  };

  const totalVulnerabilities = vulnerabilities.reduce((sum, vuln) => sum + vuln.count, 0);

  const [hoveredSlice, setHoveredSlice] = useState<string | null>(null);

  // Pie chart data processing
  const pieChartData = useMemo(() => {
    if (totalVulnerabilities === 0) return [];
    
    return vulnerabilities
      .filter(vuln => vuln.count > 0)
      .map(vuln => ({
        ...vuln,
        percentage: (vuln.count / totalVulnerabilities) * 100,
        color: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#84cc16',
          informational: '#22c55e'
        }[vuln.severity]
      }));
  }, [vulnerabilities, totalVulnerabilities]);

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Header */}
      <header className="border-b border-green-500/30 bg-black/95 backdrop-blur-sm sticky top-0 z-50 shadow-[0_0_20px_rgba(34,197,94,0.1)]">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <Shield className="w-10 h-10 text-green-400 drop-shadow-[0_0_10px_rgba(34,197,94,0.5)]" />
                <div className="flex flex-col">
                  <h1 className="text-3xl font-bold text-green-400 tracking-wider drop-shadow-[0_0_5px_rgba(34,197,94,0.3)]">
                    4postle
                  </h1>
                  <span className="text-green-500/70 text-sm tracking-widest font-mono">
                    VULNERABILITY SCANNER
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={startScan}
                disabled={isScanning}
                className="px-8 py-3 bg-gradient-to-r from-green-900/50 to-green-800/50 hover:from-green-800/70 hover:to-green-700/70 text-green-400 border border-green-500/50 rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-3 shadow-[0_0_15px_rgba(34,197,94,0.2)] hover:shadow-[0_0_25px_rgba(34,197,94,0.4)] hover:scale-105"
              >
                <Play className="w-5 h-5" />
                <span className="font-semibold tracking-wide">{isScanning ? 'SCANNING...' : 'START SCAN'}</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Target Scope Section */}
        <div className="bg-black/60 border border-green-500/30 rounded-lg p-6 mb-8 backdrop-blur-sm shadow-[0_0_30px_rgba(34,197,94,0.1)]">
          <div className="flex items-center space-x-3 mb-6">
            <Target className="w-6 h-6 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
            <h2 className="text-2xl font-bold text-green-400 tracking-wider">TARGET SCOPE</h2>
            <div className="flex-1 h-px bg-gradient-to-r from-green-500/50 to-transparent"></div>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Target Input */}
            <div className="lg:col-span-1">
              <label className="block text-sm font-medium text-green-400/80 mb-2 tracking-wide">
                TARGET URL OR IP
              </label>
              <div className="relative">
                <Globe className="absolute left-3 top-3 w-4 h-4 text-green-500/50" />
                <input
                  type="text"
                  value={targetScope.target}
                  onChange={(e) => setTargetScope(prev => ({ ...prev, target: e.target.value }))}
                  placeholder="https://example.com or 192.168.1.1"
                  className="w-full pl-10 pr-3 py-3 bg-black/80 border border-green-500/30 rounded-lg text-green-400 placeholder-green-700/50 focus:outline-none focus:border-green-400 focus:shadow-[0_0_15px_rgba(34,197,94,0.2)] transition-all duration-300 font-mono"
                />
              </div>
            </div>

            {/* In-Scope Rules - Optional */}
            <div className="lg:col-span-1">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-green-400/80 tracking-wide">
                  IN-SCOPE RULES (OPTIONAL)
                </label>
                <button
                  onClick={addInScopeRule}
                  className="text-green-400 hover:text-green-300 text-sm transition-colors duration-200 hover:drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]"
                >
                  + ADD
                </button>
              </div>
              <div className="space-y-2 max-h-32 overflow-y-auto scrollbar-thin">
                {targetScope.inScope.length === 0 ? (
                  <div className="text-green-400/50 text-sm italic text-center py-2">
                    No in-scope rules defined
                  </div>
                ) : (
                  targetScope.inScope.map((rule, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <input
                        type="text"
                        value={rule}
                        onChange={(e) => updateInScopeRule(index, e.target.value)}
                        placeholder="*.example.com"
                        className="flex-1 px-3 py-2 bg-black/80 border border-green-500/30 rounded text-green-400 placeholder-green-700/50 focus:outline-none focus:border-green-400 focus:shadow-[0_0_10px_rgba(34,197,94,0.2)] transition-all duration-300 text-sm font-mono"
                      />
                      <button
                        onClick={() => removeInScopeRule(index)}
                        className="text-red-400 hover:text-red-300 transition-colors duration-200"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Out-of-Scope Rules - Optional */}
            <div className="lg:col-span-1">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-green-400/80 tracking-wide">
                  OUT-OF-SCOPE RULES (OPTIONAL)
                </label>
                <button
                  onClick={addOutOfScopeRule}
                  className="text-green-400 hover:text-green-300 text-sm transition-colors duration-200 hover:drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]"
                >
                  + ADD
                </button>
              </div>
              <div className="space-y-2 max-h-32 overflow-y-auto scrollbar-thin">
                {targetScope.outOfScope.length === 0 ? (
                  <div className="text-green-400/50 text-sm italic text-center py-2">
                    No out-of-scope rules defined
                  </div>
                ) : (
                  targetScope.outOfScope.map((rule, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <Ban className="w-4 h-4 text-green-500/50" />
                      <input
                        type="text"
                        value={rule}
                        onChange={(e) => updateOutOfScopeRule(index, e.target.value)}
                        placeholder="admin.example.com"
                        className="flex-1 px-3 py-2 bg-black/80 border border-green-500/30 rounded text-green-400 placeholder-green-700/50 focus:outline-none focus:border-green-400 focus:shadow-[0_0_10px_rgba(34,197,94,0.2)] transition-all duration-300 text-sm font-mono"
                      />
                      <button
                        onClick={() => removeOutOfScopeRule(index)}
                        className="text-red-400 hover:text-red-300 transition-colors duration-200"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Status Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Scan Status Card */}
          <div className="lg:col-span-2 bg-black/60 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm shadow-[0_0_30px_rgba(34,197,94,0.1)]">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-3">
                {getStatusIcon()}
                <h2 className="text-2xl font-bold text-green-400 tracking-wider">SCAN STATUS</h2>
                <div className="flex-1 h-px bg-gradient-to-r from-green-500/50 to-transparent"></div>
              </div>
              <span className={`px-4 py-2 rounded-full text-sm font-semibold border tracking-wider ${
                scanStatus.state === 'scanning' ? 'border-green-400 text-green-400 animate-pulse shadow-[0_0_15px_rgba(34,197,94,0.5)]' :
                scanStatus.state === 'finished' ? 'border-green-400 text-green-400 shadow-[0_0_10px_rgba(34,197,94,0.3)]' :
                scanStatus.state === 'error' ? 'border-red-400 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.3)]' :
                'border-gray-500 text-gray-500'
              }`}>
                {scanStatus.state.toUpperCase()}
              </span>
            </div>
            
            {/* Progress Bar */}
            <div className="mb-6">
              <div className="flex justify-between text-sm mb-2">
                <span className="text-green-400/80 font-medium">PROGRESS</span>
                <span className="text-green-400 font-bold">{Math.floor(scanStatus.progress)}%</span>
              </div>
              <div className="w-full bg-black/60 rounded-full h-4 overflow-hidden border border-green-500/20">
                <div 
                  className="h-full bg-gradient-to-r from-green-600 via-green-500 to-green-400 transition-all duration-500 ease-out relative overflow-hidden"
                  style={{ width: `${scanStatus.progress}%` }}
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse"></div>
                </div>
              </div>
            </div>

            {/* Scan Logs */}
            <div className="bg-black/80 rounded-lg p-4 h-48 overflow-y-auto scrollbar-thin border border-green-500/20">
              <div className="flex items-center space-x-2 mb-3">
                <Terminal className="w-4 h-4 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
                <h3 className="text-sm font-semibold text-green-400 tracking-wider">SCAN LOGS</h3>
                <div className="flex-1 h-px bg-gradient-to-r from-green-500/30 to-transparent"></div>
              </div>
              <div className="space-y-1 text-xs">
                {scanStatus.logs.map((log, index) => (
                  <div key={index} className="flex items-start space-x-2 font-mono">
                    <span className="text-green-400 drop-shadow-[0_0_3px_rgba(34,197,94,0.5)]">{'>'}</span>
                    <span className="text-green-300/90">{log}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="bg-black/60 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm shadow-[0_0_30px_rgba(34,197,94,0.1)]">
            <div className="flex items-center space-x-3 mb-6">
              <Bug className="w-6 h-6 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
              <h2 className="text-2xl font-bold text-green-400 tracking-wider">QUICK STATS</h2>
              <div className="flex-1 h-px bg-gradient-to-r from-green-500/50 to-transparent"></div>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between items-center p-3 bg-black/40 rounded-lg border border-green-500/20">
                <span className="text-green-400/80 font-medium">Total Vulnerabilities</span>
                <span className="text-2xl font-bold text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]">{totalVulnerabilities}</span>
              </div>
              <div className="flex justify-between items-center p-3 bg-black/40 rounded-lg border border-red-500/20">
                <span className="text-red-400/80 font-medium">Critical</span>
                <span className="text-lg font-semibold text-red-400">
                  {vulnerabilities.find(v => v.severity === 'critical')?.count || 0}
                </span>
              </div>
              <div className="flex justify-between items-center p-3 bg-black/40 rounded-lg border border-orange-500/20">
                <span className="text-orange-400/80 font-medium">High</span>
                <span className="text-lg font-semibold text-orange-400">
                  {vulnerabilities.find(v => v.severity === 'high')?.count || 0}
                </span>
              </div>
              <div className="flex justify-between items-center p-3 bg-black/40 rounded-lg border border-yellow-500/20">
                <span className="text-yellow-400/80 font-medium">Medium</span>
                <span className="text-lg font-semibold text-yellow-400">
                  {vulnerabilities.find(v => v.severity === 'medium')?.count || 0}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Results Section - Only show after scan completes */}
        {showResults && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fadeIn">
            {/* Pie Chart */}
            <div className="bg-black/60 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm shadow-[0_0_30px_rgba(34,197,94,0.1)]">
              <div className="flex items-center space-x-3 mb-6">
                <Lock className="w-6 h-6 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
                <h2 className="text-2xl font-bold text-green-400 tracking-wider">VULNERABILITY DISTRIBUTION</h2>
                <div className="flex-1 h-px bg-gradient-to-r from-green-500/50 to-transparent"></div>
              </div>
            {/* Filled Pie Chart */}
            <div className="flex flex-col items-center justify-center h-80 relative">
              {totalVulnerabilities === 0 ? (
                <div className="text-center">
                  <Shield className="w-16 h-16 text-green-400/50 mx-auto mb-4" />
                  <p className="text-green-400/70 text-lg font-medium">No Vulnerabilities Found</p>
                </div>
              ) : (
                <>
                  <div className="relative w-4 h-4">
                    <svg viewBox="0 0 10 10" className="w-full h-full drop-shadow-[0_0_20px_rgba(34,197,94,0.2)]">
                      {pieChartData.map((vuln, index) => {
                        const percentage = (vuln.count / totalVulnerabilities) * 100;
                        const angle = (percentage / 100) * 360;
                        const startAngle = index === 0 ? -90 : pieChartData.slice(0, index).reduce((sum, v) => sum + (v.count / totalVulnerabilities) * 360, 0) - 90;
                        const endAngle = startAngle + angle;
                        const isHovered = hoveredSlice === vuln.severity;
                        
                        // Convert angles to radians
                        const startAngleRad = (startAngle * Math.PI) / 180;
                        const endAngleRad = (endAngle * Math.PI) / 180;
                        
                        // Calculate path coordinates for 10x10 viewBox
                        const x1 = 5 + 4.5 * Math.cos(startAngleRad);
                        const y1 = 5 + 4.5 * Math.sin(startAngleRad);
                        const x2 = 5 + 4.5 * Math.cos(endAngleRad);
                        const y2 = 5 + 4.5 * Math.sin(endAngleRad);
                        
                        const largeArcFlag = angle > 180 ? 1 : 0;
                        
                        // Calculate text position (middle of the slice)
                        const midAngleRad = ((startAngle + endAngle) / 2 * Math.PI) / 180;
                        const textRadius = 3; // Position text closer to center
                        const textX = 5 + textRadius * Math.cos(midAngleRad);
                        const textY = 5 + textRadius * Math.sin(midAngleRad);
                        
                        const pathData = [
                          `M 5 5`,
                          `L ${x1} ${y1}`,
                          `A 4.5 4.5 0 ${largeArcFlag} 1 ${x2} ${y2}`,
                          'Z'
                        ].join(' ');
                        
                        return (
                          <g key={vuln.id}>
                            <path
                              d={pathData}
                              fill={vuln.color}
                              className="transition-all duration-300 cursor-pointer"
                              style={{
                                filter: isHovered ? 'brightness(1.2) drop-shadow(0 0 10px rgba(34, 197, 94, 0.5))' : 'none',
                                transform: isHovered ? 'scale(1.05)' : 'scale(1)',
                                transformOrigin: '5px 5px'
                              }}
                              onMouseEnter={() => setHoveredSlice(vuln.severity)}
                              onMouseLeave={() => setHoveredSlice(null)}
                            />
                            {/* Text label inside slice */}
                            {percentage > 15 && ( // Only show text if slice is large enough
                              <text
                                x={textX}
                                y={textY}
                                textAnchor="middle"
                                dominantBaseline="middle"
                                className="font-bold fill-white pointer-events-none"
                                style={{
                                  textShadow: '0 0 1px rgba(0, 0, 0, 0.8)',
                                  fontSize: '1px'
                                }}
                              >
                                {vuln.severity.charAt(0).toUpperCase()}
                              </text>
                            )}
                          </g>
                        );
                      })}
                    </svg>
                    
                    {/* Tooltip */}
                    {hoveredSlice && (
                      <div className="absolute top-4 right-4 bg-black/95 border border-green-500/50 rounded-lg p-3 backdrop-blur-sm shadow-[0_0_20px_rgba(34,197,94,0.3)] z-10">
                        <div className="flex items-center space-x-2 mb-2">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: pieChartData.find(item => item.severity === hoveredSlice)?.color }}
                          />
                          <span className="text-green-300 font-semibold text-sm capitalize">
                            {hoveredSlice}
                          </span>
                        </div>
                        <div className="text-green-400/80 text-xs">
                          Count: <span className="text-green-400 font-bold">
                            {pieChartData.find(item => item.severity === hoveredSlice)?.count || 0}
                          </span>
                        </div>
                        <div className="text-green-400/80 text-xs">
                          Percentage: <span className="text-green-400 font-bold">
                            {pieChartData.find(item => item.severity === hoveredSlice)?.percentage.toFixed(1) || 0}%
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {/* Legend with Labels */}
                  <div className="mt-6 space-y-2 w-full max-w-sm">
                    {pieChartData.map((vuln) => (
                      <div 
                        key={vuln.id} 
                        className="flex items-center justify-between p-3 rounded hover:bg-black/40 transition-all duration-200 cursor-pointer border border-transparent hover:border-green-500/20"
                        onMouseEnter={() => setHoveredSlice(vuln.severity)}
                        onMouseLeave={() => setHoveredSlice(null)}
                      >
                        <div className="flex items-center space-x-3">
                          <div 
                            className="w-4 h-4 rounded-full shadow-lg border border-black/30" 
                            style={{ backgroundColor: vuln.color }}
                          />
                          <div>
                            <span className="text-sm text-green-300/90 font-medium capitalize">{vuln.severity}</span>
                            <div className="text-xs text-green-400/60">{vuln.title}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-bold text-green-400">{vuln.count}</div>
                          <div className="text-xs text-green-400/60">{vuln.percentage.toFixed(1)}%</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
            </div>

            {/* Recent Vulnerabilities */}
            <div className="bg-black/60 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm shadow-[0_0_30px_rgba(34,197,94,0.1)]">
              <div className="flex items-center space-x-3 mb-6">
                <AlertTriangle className="w-6 h-6 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]" />
                <h2 className="text-2xl font-bold text-green-400 tracking-wider">RECENT FINDINGS</h2>
                <div className="flex-1 h-px bg-gradient-to-r from-green-500/50 to-transparent"></div>
              </div>
              <div className="space-y-3">
                {vulnerabilities.slice(0, 5).map((vuln) => (
                  <div key={vuln.id} className={`border rounded-lg p-4 hover:bg-black/40 transition-all duration-200 ${getSeverityColor(vuln.severity)} bg-black/20`}>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h3 className="font-semibold text-sm mb-2 text-green-300/90">{vuln.title}</h3>
                        <p className="text-xs text-green-400/70 leading-relaxed">{vuln.description}</p>
                      </div>
                      <span className={`ml-3 px-3 py-1 rounded text-xs font-bold border tracking-wider shadow-lg ${
                        vuln.severity === 'critical' ? 'bg-red-900/30 text-red-400 border-red-400/50 shadow-red-500/30' :
                        vuln.severity === 'high' ? 'bg-orange-900/30 text-orange-400 border-orange-400/50 shadow-orange-500/30' :
                        vuln.severity === 'medium' ? 'bg-yellow-900/30 text-yellow-400 border-yellow-400/50 shadow-yellow-500/30' :
                        vuln.severity === 'low' ? 'bg-lime-900/30 text-lime-400 border-lime-400/50 shadow-lime-500/30' :
                        'bg-green-900/30 text-green-400 border-green-400/50 shadow-green-500/30'
                      }`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>

      <style jsx>{`
        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-fadeIn {
          animation: fadeIn 0.5s ease-out;
        }
      `}</style>
    </div>
  );
}
