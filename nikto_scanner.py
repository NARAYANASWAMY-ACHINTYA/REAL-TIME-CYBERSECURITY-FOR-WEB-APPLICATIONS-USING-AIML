import re
import tempfile
from typing import Dict, List, Generator, Union
import os
from urllib.parse import urlparse
from datetime import datetime
import signal
import requests
import socket
from concurrent.futures import ThreadPoolExecutor
import urllib3
from bs4 import BeautifulSoup
import threading
import socket
from OpenSSL import SSL

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityTest:
    def __init__(self, name: str, category: str, description: str, solution: str, cvss_score: float):
        self.name = name
        self.category = category
        self.description = description
        self.solution = solution
        self.cvss_score = cvss_score
        self.risk_level = self._determine_risk_level()
        self.timestamp = datetime.now().isoformat()
        self.references = []
        self.proof_of_concept = None
        self.status = "vulnerable"  # Can be "vulnerable", "secure", or "info"

    def _determine_risk_level(self) -> str:
        if self.cvss_score >= 7.0:
            return "high"
        elif self.cvss_score >= 4.0:
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "solution": self.solution,
            "cvss_score": self.cvss_score,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
            "references": self.references,
            "proof_of_concept": self.proof_of_concept,
            "status": self.status
        }

class NiktoScanner:
    def __init__(self):
        self.temp_dir = tempfile.gettempdir()
        self.current_process = None
        self.session = requests.Session()
        self.session.verify = False
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self._stop_event = threading.Event()
        self.scan_progress = 0
        self.total_tests = 0
        self.completed_tests = 0

    def _make_request(self, url: str, method: str = 'GET', timeout: int = 10, **kwargs) -> requests.Response:
        """Make HTTP/HTTPS request with proper error handling and timeout."""
        kwargs['timeout'] = timeout
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                try:
                    http_url = f"http://{url}"
                    return self.session.request(method, http_url, **kwargs)
                except requests.exceptions.RequestException:
                    https_url = f"https://{url}"
                    return self.session.request(method, https_url, **kwargs)
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.Timeout:
            raise Exception(f"Request timed out after {timeout} seconds")
        except requests.exceptions.SSLError:
            kwargs['verify'] = False
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")

    def _update_progress(self):
        """Update scan progress."""
        self.completed_tests += 1
        self.scan_progress = (self.completed_tests / self.total_tests) * 100

    def test_ssl_tls(self, hostname: str, port: int = 443) -> SecurityTest:
        """Test SSL/TLS configuration."""
        try:
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            ssl_sock = SSL.Connection(context, sock)
            ssl_sock.connect((hostname, port))
            ssl_sock.do_handshake()
            cert = ssl_sock.get_peer_certificate()
            
            issues = []
            if cert.get_notAfter() < datetime.now().strftime('%Y%m%d%H%M%SZ'):
                issues.append("Expired certificate")
            if cert.get_signature_algorithm().decode() in ['sha1WithRSAEncryption', 'md5WithRSAEncryption']:
                issues.append("Weak signature algorithm")
            
            if issues:
                return SecurityTest(
                    "SSL/TLS Configuration Issues",
                    "Transport Layer Security",
                    f"SSL/TLS issues found: {', '.join(issues)}",
                    "Update SSL/TLS configuration and certificates",
                    7.5
                )
            else:
                result = SecurityTest(
                    "SSL/TLS Configuration",
                    "Transport Layer Security",
                    "SSL/TLS configuration appears secure",
                    "Continue monitoring for certificate expiration and new vulnerabilities",
                    0.0
                )
                result.status = "secure"
                return result
        except Exception as e:
            if "protocol_version" in str(e):
                return SecurityTest(
                    "Outdated SSL/TLS Version",
                    "Transport Layer Security",
                    "Server supports outdated SSL/TLS versions",
                    "Disable old SSL/TLS versions and enable only TLS 1.2+",
                    8.0
                )
            result = SecurityTest(
                "SSL/TLS Not Available",
                "Transport Layer Security",
                "Could not establish SSL/TLS connection",
                "Implement HTTPS with valid certificates",
                5.0
            )
            result.status = "info"
            return result

    def test_security_headers(self, url: str) -> List[SecurityTest]:
        """Test for missing security headers."""
        results = []
        try:
            response = self._make_request(url)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': {
                    'description': 'Missing HSTS header',
                    'solution': 'Add Strict-Transport-Security header with appropriate max-age',
                    'cvss': 6.5
                },
                'X-Frame-Options': {
                    'description': 'Missing X-Frame-Options header (clickjacking protection)',
                    'solution': 'Add X-Frame-Options header set to DENY or SAMEORIGIN',
                    'cvss': 5.0
                },
                'X-Content-Type-Options': {
                    'description': 'Missing X-Content-Type-Options header',
                    'solution': 'Add X-Content-Type-Options header set to nosniff',
                    'cvss': 4.0
                },
                'Content-Security-Policy': {
                    'description': 'Missing Content Security Policy',
                    'solution': 'Implement a strict Content Security Policy',
                    'cvss': 6.0
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    results.append(SecurityTest(
                        f"Missing {header}",
                        "Security Headers",
                        info['description'],
                        info['solution'],
                        info['cvss']
                    ))
            
        except Exception as e:
            pass
        return results

    def test_sql_injection(self, url: str) -> SecurityTest:
        """Test for SQL injection vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '0:0:5'--"
        ]
        
        base_response_time = 0
        try:
            start_time = datetime.now()
            self._make_request(url)
            base_response_time = (datetime.now() - start_time).total_seconds()
            
            for payload in payloads:
                params = {'id': payload}
                response = self._make_request(url, params=params)
                
                # Time-based detection
                injection_time = (datetime.now() - start_time).total_seconds()
                if injection_time > base_response_time * 3:
                    return SecurityTest(
                        "SQL Injection Vulnerability",
                        "Injection",
                        f"Potential time-based SQL injection with payload: {payload}",
                        "1. Use parameterized queries\n2. Implement input validation\n3. Use an ORM\n4. Apply principle of least privilege",
                        9.0
                    )
                
                # Error-based detection
                if any(err in response.text.lower() for err in [
                    'sql', 'mysql', 'sqlite', 'postgresql', 'ora-', 'error in your sql syntax'
                ]):
                    return SecurityTest(
                        "SQL Injection Vulnerability",
                        "Injection",
                        f"SQL injection vulnerability detected with payload: {payload}",
                        "1. Use parameterized queries\n2. Implement input validation\n3. Use an ORM\n4. Apply principle of least privilege",
                        9.0
                    )
        except:
            pass
        return None

    def test_xss(self, url: str) -> SecurityTest:
        """Test for XSS vulnerabilities."""
        payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            '<svg/onload=alert(1)>',
            '\'><script>alert(document.cookie)</script>'
        ]
        
        try:
            for payload in payloads:
                params = {'q': payload}
                response = self._make_request(url, params=params)
                if payload in response.text:
                    return SecurityTest(
                        "Cross-Site Scripting (XSS)",
                        "Injection",
                        f"XSS vulnerability detected with payload: {payload}",
                        "1. Implement input validation\n2. Use content security policy\n3. Encode output\n4. Use security headers",
                        7.5
                    )
                    
            # Test for DOM XSS
            response = self._make_request(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            risky_patterns = [
                'document.write',
                'document.location',
                'window.location',
                'eval(',
                'innerHTML',
                'outerHTML'
            ]
            
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and any(pattern in script.string for pattern in risky_patterns):
                    return SecurityTest(
                        "Potential DOM-based XSS",
                        "Injection",
                        "Potentially unsafe JavaScript patterns detected",
                        "1. Avoid unsafe JavaScript patterns\n2. Implement CSP\n3. Use safe DOM manipulation methods",
                        6.5
                    )
        except:
            pass
        return None

    def test_directory_traversal(self, url: str) -> SecurityTest:
        """Test for directory traversal vulnerabilities."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        try:
            for payload in payloads:
                test_url = f"{url}?file={payload}"
                response = self._make_request(test_url)
                
                if any(pattern in response.text for pattern in [
                    "root:x:", "root:[x*]:", "[boot loader]", "[fonts]"
                ]):
                    return SecurityTest(
                        "Directory Traversal",
                        "File System",
                        f"Directory traversal vulnerability detected with payload: {payload}",
                        "1. Validate file paths\n2. Use whitelisting\n3. Implement proper access controls",
                        8.0
                    )
        except:
            pass
        return None

    def test_open_redirect(self, url: str) -> SecurityTest:
        """Test for open redirect vulnerabilities."""
        payloads = [
            "https://evil.com",
            "//evil.com",
            "\\\\evil.com",
            "javascript:alert(document.domain)"
        ]
        
        try:
            for payload in payloads:
                params = {'redirect': payload, 'url': payload, 'next': payload}
                response = self._make_request(url, params=params, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if payload in location or 'evil.com' in location:
                        return SecurityTest(
                            "Open Redirect",
                            "Access Control",
                            f"Open redirect vulnerability detected with payload: {payload}",
                            "1. Validate redirect URLs\n2. Use whitelist of allowed domains\n3. Implement proper URL parsing",
                            6.0
                        )
        except:
            pass
        return None

    def test_csrf(self, url: str) -> SecurityTest:
        """Test for CSRF vulnerabilities."""
        try:
            response = self._make_request(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                csrf_tokens = form.find_all('input', attrs={
                    'type': 'hidden',
                    'name': re.compile(r'csrf|token|nonce', re.I)
                })
                
                if not csrf_tokens:
                    return SecurityTest(
                        "Cross-Site Request Forgery (CSRF)",
                        "Access Control",
                        "Form found without CSRF protection",
                        "1. Implement CSRF tokens\n2. Use SameSite cookie attribute\n3. Verify origin headers",
                        7.0
                    )
        except:
            pass
        return None

    def scan(self, target_url: str, timeout: int = 300) -> Generator[Union[str, Dict], None, None]:
        """
        Perform a comprehensive security scan of the target URL.
        
        Args:
            target_url: The URL to scan
            timeout: Maximum time in seconds for the entire scan
        """
        self._stop_event.clear()
        self.scan_progress = 0
        start_time = datetime.now()
        
        try:
            yield "Starting comprehensive security scan..."
            
            # Basic URL validation and normalization
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'http://{target_url}'
            
            parsed_url = urlparse(target_url)
            if not parsed_url.netloc:
                raise ValueError("Invalid URL provided")
            
            # Initialize test suite
            test_methods = [
                (self.test_ssl_tls, [parsed_url.netloc]),
                (self.test_security_headers, [target_url]),
                (self.test_sql_injection, [target_url]),
                (self.test_xss, [target_url]),
                (self.test_directory_traversal, [target_url]),
                (self.test_open_redirect, [target_url]),
                (self.test_csrf, [target_url])
            ]
            
            self.total_tests = len(test_methods)
            self.completed_tests = 0
            
            # Track test results for summary
            test_results = {
                'vulnerable': [],
                'secure': [],
                'info': [],
                'error': []
            }
            
            # Run tests with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                for test_method, args in test_methods:
                    if self._stop_event.is_set():
                        yield "Scan stopped by user"
                        return
                        
                    if (datetime.now() - start_time).total_seconds() > timeout:
                        yield "Scan timed out"
                        return
                    
                    futures.append(executor.submit(test_method, *args))
                
                # Process results as they complete
                for future in futures:
                    try:
                        if self._stop_event.is_set():
                            yield "Scan stopped by user"
                            return
                            
                        if (datetime.now() - start_time).total_seconds() > timeout:
                            yield "Scan timed out"
                            return
                        
                        result = future.result(timeout=max(1, timeout - (datetime.now() - start_time).total_seconds()))
                        if result:
                            if isinstance(result, list):
                                for item in result:
                                    test_results[item.status].append(item.to_dict())
                                    yield item.to_dict()
                            else:
                                test_results[result.status].append(result.to_dict())
                                yield result.to_dict()
                        else:
                            # If no result, add an info result
                            info_result = SecurityTest(
                                "Test Completed",
                                "Information",
                                "No issues found in this test",
                                "Continue monitoring and regular security testing",
                                0.0
                            )
                            info_result.status = "info"
                            test_results['info'].append(info_result.to_dict())
                            yield info_result.to_dict()
                        
                        self._update_progress()
                        yield {
                            'type': 'progress',
                            'percentage': self.scan_progress,
                            'completed': self.completed_tests,
                            'total': self.total_tests
                        }
                        
                    except Exception as e:
                        error_result = SecurityTest(
                            "Test Error",
                            "Error",
                            f"Error during test: {str(e)}",
                            "Review server logs and try again",
                            0.0
                        )
                        error_result.status = "error"
                        test_results['error'].append(error_result.to_dict())
                        yield error_result.to_dict()
                        self._update_progress()
                
                # Generate summary
                yield {
                    'type': 'summary',
                    'data': {
                        'total_tests': self.total_tests,
                        'vulnerabilities_found': len(test_results['vulnerable']),
                        'secure_components': len(test_results['secure']),
                        'info_messages': len(test_results['info']),
                        'errors': len(test_results['error']),
                        'test_results': test_results
                    }
                }
                
        except Exception as e:
            yield f"Scan error: {str(e)}"
        finally:
            self._stop_event.clear()
            self.scan_progress = 100
            yield {
                'type': 'progress',
                'percentage': 100,
                'completed': self.total_tests,
                'total': self.total_tests
            }

    def stop_scan(self):
        """Stop the current scan."""
        self._stop_event.set()
        if self.current_process and self.current_process.poll() is None:
            try:
                os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
            except:
                pass
            self.current_process = None
            self.session.close() 