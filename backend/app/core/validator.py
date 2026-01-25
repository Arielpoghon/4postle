"""
4postle Vulnerability Validation Engine
Critical phase to eliminate false positives and validate findings
"""

import asyncio
import aiohttp
import re
import json
import base64
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs
import time
import random
import string

from app.core.scanner import Vulnerability, Severity

@dataclass
class ValidationRequest:
    vulnerability: Vulnerability
    original_request: Optional[str]
    original_response: Optional[str]
    validation_attempts: int = 0
    max_attempts: int = 3

@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any]
    error_message: Optional[str]
    validation_time: float

class VulnerabilityValidator:
    def __init__(self, timeout: int = 30, max_concurrent: int = 5):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        self.validation_cache: Dict[str, ValidationResult] = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(limit=self.max_concurrent)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def validate_vulnerability(self, vuln: Vulnerability) -> ValidationResult:
        """
        Main validation entry point
        Routes to specific validation based on vulnerability type
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(vuln)
        if cache_key in self.validation_cache:
            cached_result = self.validation_cache[cache_key]
            cached_result.validation_time = time.time() - start_time
            return cached_result
        
        try:
            # Route to appropriate validator
            if vuln.vulnerability_type.lower() in ["sql injection", "sqli"]:
                result = await self._validate_sql_injection(vuln)
            elif vuln.vulnerability_type.lower() in ["xss", "cross-site scripting"]:
                result = await self._validate_xss(vuln)
            elif vuln.vulnerability_type.lower() in ["ssrf"]:
                result = await self._validate_ssrf(vuln)
            elif vuln.vulnerability_type.lower() in ["idor", "insecure direct object reference"]:
                result = await self._validate_idor(vuln)
            elif vuln.vulnerability_type.lower() in ["cors", "cors misconfiguration"]:
                result = await self._validate_cors(vuln)
            elif vuln.vulnerability_type.lower() in ["lfi", "local file inclusion"]:
                result = await self._validate_lfi(vuln)
            elif vuln.vulnerability_type.lower() in ["rce", "remote code execution"]:
                result = await self._validate_rce(vuln)
            elif vuln.vulnerability_type.lower() in ["open redirect"]:
                result = await self._validate_open_redirect(vuln)
            else:
                result = await self._validate_generic(vuln)
            
            result.validation_time = time.time() - start_time
            
            # Cache result
            self.validation_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence={},
                error_message=f"Validation error: {str(e)}",
                validation_time=time.time() - start_time
            )
    
    async def _validate_sql_injection(self, vuln: Vulnerability) -> ValidationResult:
        """Validate SQL injection vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # SQL injection payloads for validation
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "admin'--"
        ]
        
        # Error patterns to detect SQL errors
        sql_errors = [
            "SQL syntax.*MySQL",
            "Warning.*mysql_.*",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PostgreSQL query failed",
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "Microsoft OLE DB Provider",
            "ODBC Microsoft Access",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "oracle\\.jdbc",
            "Oracle error",
            "CLI Driver.*DB2",
            "DB2 SQL error",
            "SQLJDBC",
            "com\\.mysql\\.jdbc",
            "PSQLException",
            "org\\.h2",
            "java\\.sql\\.SQLException",
            "Macromedia.*SQL",
            "ORA-[0-9]{5}",
            "PLS-[0-9]{5}",
            "MySQLSyntaxErrorException",
            "SQLServerException"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "id"
        
        try:
            # Test with legitimate value first
            legit_response = await self._make_request(f"{base_url}?{param}=1")
            legit_content = await legit_response.text() if legit_response else ""
            
            # Test SQL payloads
            for payload in payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = await self._make_request(test_url)
                
                if response:
                    content = await response.text()
                    
                    # Check for SQL errors
                    for error_pattern in sql_errors:
                        if re.search(error_pattern, content, re.IGNORECASE):
                            evidence["sql_error"] = {
                                "payload": payload,
                                "error": re.search(error_pattern, content, re.IGNORECASE).group(),
                                "response_length": len(content)
                            }
                            confidence = max(confidence, 0.8)
                            break
                    
                    # Check for response differences (blind SQLi)
                    if len(content) != len(legit_content):
                        if "sql_error" not in evidence:
                            evidence["response_difference"] = {
                                "payload": payload,
                                "legit_length": len(legit_content),
                                "test_length": len(content),
                                "difference": abs(len(content) - len(legit_content))
                            }
                            confidence = max(confidence, 0.6)
            
            # Time-based validation
            time_payload = "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            start_time = time.time()
            response = await self._make_request(f"{base_url}?{param}={time_payload}")
            end_time = time.time()
            
            if end_time - start_time >= 4:  # Account for network latency
                evidence["time_based"] = {
                    "payload": time_payload,
                    "response_time": end_time - start_time
                }
                confidence = max(confidence, 0.9)
            
            is_valid = confidence >= 0.6
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for SQL injection"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"SQL injection validation error: {str(e)}", 0.0)
    
    async def _validate_xss(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Cross-Site Scripting vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # Generate unique XSS payload
        xss_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        payloads = [
            f"<script>alert('{xss_id}')</script>",
            f"<img src=x onerror=alert('{xss_id}')>",
            f"'><script>alert('{xss_id}')</script>",
            f"javascript:alert('{xss_id}')",
            f"<svg onload=alert('{xss_id}')>"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "input"
        
        try:
            for payload in payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = await self._make_request(test_url)
                
                if response:
                    content = await response.text()
                    
                    # Check if payload is reflected in response
                    if xss_id in content:
                        evidence["reflected"] = {
                            "payload": payload,
                            "xss_id": xss_id,
                            "reflection_count": content.count(xss_id)
                        }
                        confidence = max(confidence, 0.7)
                    
                    # Check for script tag reflection
                    if "<script>" in content.lower() or "onerror=" in content.lower():
                        evidence["script_reflection"] = {
                            "payload": payload,
                            "reflection": True
                        }
                        confidence = max(confidence, 0.8)
            
            # Test stored XSS if applicable
            if vuln.vulnerability_type.lower() == "stored xss":
                # Check if payload persists after navigation
                stored_confidence = await self._validate_stored_xss(base_url, xss_id)
                confidence = max(confidence, stored_confidence)
            
            is_valid = confidence >= 0.6
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for XSS"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"XSS validation error: {str(e)}", 0.0)
    
    async def _validate_ssrf(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Server-Side Request Forgery vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # SSRF test payloads
        test_urls = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "file:///etc/passwd",
            "http://example.com"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "url"
        
        try:
            for test_url in test_urls:
                test_endpoint = f"{base_url}?{param}={test_url}"
                response = await self._make_request(test_endpoint)
                
                if response:
                    content = await response.text()
                    
                    # Check for successful SSRF indicators
                    if "example.com" in test_url and "Example Domain" in content:
                        evidence["external_request"] = {
                            "payload": test_url,
                            "response_length": len(content),
                            "indicator": "example.com content"
                        }
                        confidence = max(confidence, 0.8)
                    
                    # Check for localhost responses
                    if "127.0.0.1" in test_url or "localhost" in test_url:
                        if len(content) > 100:  # Likely got a response
                            evidence["internal_request"] = {
                                "payload": test_url,
                                "response_length": len(content)
                            }
                            confidence = max(confidence, 0.9)
                    
                    # Check for file inclusion
                    if "file://" in test_url and "root:" in content:
                        evidence["file_inclusion"] = {
                            "payload": test_url,
                            "evidence": "File content detected"
                        }
                        confidence = max(confidence, 0.9)
            
            is_valid = confidence >= 0.7
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for SSRF"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"SSRF validation error: {str(e)}", 0.0)
    
    async def _validate_idor(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Insecure Direct Object Reference vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        try:
            # Extract ID from current endpoint
            url_parts = urlparse(vuln.endpoint)
            query_params = parse_qs(url_parts.query)
            
            # Find ID parameter
            id_param = vuln.parameter or "id"
            current_id = None
            
            if id_param in query_params:
                current_id = query_params[id_param][0]
            else:
                # Try to extract from path
                path_parts = url_parts.path.split('/')
                for part in path_parts:
                    if part.isdigit():
                        current_id = part
                        break
            
            if not current_id:
                return ValidationResult(False, 0.0, {}, "No ID parameter found", 0.0)
            
            # Test with different IDs
            test_ids = [str(int(current_id) + 1), str(int(current_id) - 1), "1", "999999"]
            
            base_url = vuln.endpoint
            original_response = await self._make_request(base_url)
            original_content = await original_response.text() if original_response else ""
            
            for test_id in test_ids:
                if id_param in query_params:
                    test_url = vuln.endpoint.replace(f"{id_param}={current_id}", f"{id_param}={test_id}")
                else:
                    test_url = vuln.endpoint.replace(current_id, test_id)
                
                response = await self._make_request(test_url)
                
                if response:
                    content = await response.text()
                    
                    # Check if we can access different user data
                    if len(content) > 100 and content != original_content:
                        evidence["unauthorized_access"] = {
                            "original_id": current_id,
                            "test_id": test_id,
                            "response_length": len(content),
                            "different_content": True
                        }
                        confidence = max(confidence, 0.8)
                        
                        # Look for user-specific data patterns
                        user_patterns = [r"email\s*[:=]\s*[\w@.-]+", r"user\s*[:=]\s*\w+", r"name\s*[:=]\s*\w+"]
                        for pattern in user_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                evidence["user_data"] = {
                                    "pattern": pattern,
                                    "found": True
                                }
                                confidence = max(confidence, 0.9)
                                break
            
            is_valid = confidence >= 0.7
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for IDOR"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"IDOR validation error: {str(e)}", 0.0)
    
    async def _validate_cors(self, vuln: Vulnerability) -> ValidationResult:
        """Validate CORS misconfiguration vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        try:
            # Test CORS headers
            headers = {
                "Origin": "https://evil.com",
                "Referer": "https://evil.com"
            }
            
            response = await self._make_request(vuln.endpoint, headers=headers)
            
            if response:
                cors_headers = {
                    "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
                    "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
                    "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
                    "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials")
                }
                
                # Check for overly permissive CORS
                acao = cors_headers["Access-Control-Allow-Origin"]
                if acao and (acao == "*" or "evil.com" in acao):
                    evidence["permissive_origin"] = {
                        "allowed_origin": acao,
                        "test_origin": "https://evil.com"
                    }
                    confidence = max(confidence, 0.8)
                
                # Check for credentials with wildcard origin
                if acao == "*" and cors_headers["Access-Control-Allow-Credentials"] == "true":
                    evidence["dangerous_creds"] = {
                        "origin": acao,
                        "credentials": cors_headers["Access-Control-Allow-Credentials"]
                    }
                    confidence = max(confidence, 0.9)
                
                # Test preflight request
                preflight_headers = {
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type"
                }
                
                preflight_response = await self._make_request(
                    vuln.endpoint, 
                    method="OPTIONS",
                    headers=preflight_headers
                )
                
                if preflight_response and preflight_response.status == 200:
                    evidence["preflight_allowed"] = {
                        "status": preflight_response.status,
                        "headers": dict(preflight_response.headers)
                    }
                    confidence = max(confidence, 0.8)
            
            is_valid = confidence >= 0.6
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for CORS misconfiguration"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"CORS validation error: {str(e)}", 0.0)
    
    async def _validate_lfi(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Local File Inclusion vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # LFI test payloads
        payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "file"
        
        try:
            for payload in payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = await self._make_request(test_url)
                
                if response:
                    content = await response.text()
                    
                    # Check for file content indicators
                    if "root:" in content and "/bin/bash" in content:
                        evidence["passwd_file"] = {
                            "payload": payload,
                            "evidence": "Unix passwd file content"
                        }
                        confidence = max(confidence, 0.9)
                    
                    if "localhost" in content and "#" in content:
                        evidence["hosts_file"] = {
                            "payload": payload,
                            "evidence": "Windows hosts file content"
                        }
                        confidence = max(confidence, 0.9)
                    
                    # Check for base64 encoded content
                    if "php://filter" in payload and len(content) > 100:
                        try:
                            decoded = base64.b64decode(content).decode('utf-8')
                            if "root:" in decoded:
                                evidence["base64_file"] = {
                                    "payload": payload,
                                    "decoded_content": decoded[:100] + "..."
                                }
                                confidence = max(confidence, 0.9)
                        except:
                            pass
            
            is_valid = confidence >= 0.7
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for LFI"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"LFI validation error: {str(e)}", 0.0)
    
    async def _validate_rce(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Remote Code Execution vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # Generate unique command identifier
        cmd_id = ''.join(random.choices(string.ascii_letters, k=8))
        payloads = [
            f"echo {cmd_id}",
            f"whoami; echo {cmd_id}",
            f"dir && echo {cmd_id}",
            f"ls -la && echo {cmd_id}",
            f"id; echo {cmd_id}"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "cmd"
        
        try:
            for payload in payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = await self._make_request(test_url)
                
                if response:
                    content = await response.text()
                    
                    # Check for our command identifier
                    if cmd_id in content:
                        evidence["command_execution"] = {
                            "payload": payload,
                            "cmd_id": cmd_id,
                            "response": content
                        }
                        confidence = max(confidence, 0.9)
                    
                    # Check for system command outputs
                    system_outputs = ["root:", "uid=", "gid=", "Volume Serial Number", "Directory of"]
                    for output in system_outputs:
                        if output in content:
                            evidence["system_output"] = {
                                "payload": payload,
                                "output": output
                            }
                            confidence = max(confidence, 0.8)
            
            is_valid = confidence >= 0.8
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for RCE"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"RCE validation error: {str(e)}", 0.0)
    
    async def _validate_open_redirect(self, vuln: Vulnerability) -> ValidationResult:
        """Validate Open Redirect vulnerabilities"""
        evidence = {}
        confidence = 0.0
        
        if not self.session or not vuln.endpoint:
            return ValidationResult(False, 0.0, {}, "No session or endpoint", 0.0)
        
        # Test redirect payloads
        test_urls = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "http://example.com@evil.com",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        base_url = vuln.endpoint
        param = vuln.parameter or "redirect" or "url" or "return"
        
        try:
            for test_url in test_urls:
                test_endpoint = f"{base_url}?{param}={test_url}"
                response = await self._make_request(test_endpoint, allow_redirects=False)
                
                if response:
                    # Check for redirect headers
                    location = response.headers.get("Location", "")
                    if "evil.com" in location:
                        evidence["redirect_header"] = {
                            "payload": test_url,
                            "location": location
                        }
                        confidence = max(confidence, 0.9)
                    
                    # Check for meta refresh or JavaScript redirects
                    content = await response.text()
                    if "evil.com" in content.lower():
                        evidence["redirect_content"] = {
                            "payload": test_url,
                            "content_snippet": content[:200]
                        }
                        confidence = max(confidence, 0.8)
            
            is_valid = confidence >= 0.7
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Insufficient evidence for Open Redirect"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"Open Redirect validation error: {str(e)}", 0.0)
    
    async def _validate_generic(self, vuln: Vulnerability) -> ValidationResult:
        """Generic validation for other vulnerability types"""
        evidence = {}
        confidence = 0.3  # Low confidence for generic validation
        
        try:
            # Basic validation - check if endpoint is accessible
            if self.session and vuln.endpoint:
                response = await self._make_request(vuln.endpoint)
                if response and response.status == 200:
                    evidence["endpoint_accessible"] = {
                        "status_code": response.status,
                        "content_length": len(await response.text())
                    }
                    confidence = 0.5
            
            is_valid = confidence >= 0.4
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=evidence,
                error_message=None if is_valid else "Generic validation - low confidence"
            )
            
        except Exception as e:
            return ValidationResult(False, 0.0, {}, f"Generic validation error: {str(e)}", 0.0)
    
    async def _validate_stored_xss(self, base_url: str, xss_id: str) -> float:
        """Validate stored XSS by checking persistence"""
        try:
            # Wait a moment for storage
            await asyncio.sleep(2)
            
            # Check if XSS payload persists
            response = await self._make_request(base_url)
            if response:
                content = await response.text()
                if xss_id in content:
                    return 0.9
        except:
            pass
        
        return 0.0
    
    async def _make_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None, 
                          allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with error handling"""
        try:
            if not self.session:
                return None
            
            request_headers = {
                "User-Agent": "4postle/1.0 (Vulnerability Scanner)",
                "Accept": "*/*"
            }
            
            if headers:
                request_headers.update(headers)
            
            async with self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                allow_redirects=allow_redirects,
                ssl=False  # Allow self-signed certs
            ) as response:
                return response
                
        except Exception as e:
            return None
    
    def _generate_cache_key(self, vuln: Vulnerability) -> str:
        """Generate cache key for vulnerability"""
        key_data = f"{vuln.endpoint}:{vuln.parameter}:{vuln.vulnerability_type}"
        return hashlib.md5(key_data.encode()).hexdigest()

# CVSS Score Calculator
class CVSSCalculator:
    """Calculate CVSS scores for vulnerabilities"""
    
    @staticmethod
    def calculate_cvss_score(vuln: Vulnerability) -> float:
        """
        Calculate CVSS v3.1 score based on vulnerability characteristics
        Simplified implementation for demonstration
        """
        
        # Base score mapping by severity
        base_scores = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0
        }
        
        base_score = base_scores.get(vuln.severity, 0.0)
        
        # Adjust based on vulnerability type
        type_modifiers = {
            "sql injection": 0.5,
            "xss": 0.3,
            "rce": 0.7,
            "ssrf": 0.4,
            "idor": 0.3,
            "lfi": 0.4,
            "open redirect": 0.2,
            "cors": 0.1
        }
        
        modifier = type_modifiers.get(vuln.vulnerability_type.lower(), 0.0)
        
        # Adjust based on exploitability
        if vuln.validated:
            modifier += 0.2
        
        # Calculate final score
        final_score = min(10.0, base_score + modifier)
        
        return round(final_score, 1)
    
    @staticmethod
    def get_severity_from_cvss(cvss_score: float) -> Severity:
        """Get severity level from CVSS score"""
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        elif cvss_score > 0.0:
            return Severity.LOW
        else:
            return Severity.INFO
