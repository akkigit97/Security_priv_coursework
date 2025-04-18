import requests
import time
import random
import string
from colorama import init, Fore, Style
from security_defenses import SecurityDefenses
import dns.resolver

# Initialize colorama
init()

class SecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.defenses = SecurityDefenses()
        self.session = requests.Session()
        self.test_results = []
        
    def test_rate_limiting(self):
        """Test rate limiting protection"""
        print(f"\n{Fore.YELLOW}[*] Testing Rate Limiting...{Style.RESET_ALL}")
        results = []
        
        # Make rapid requests
        for i in range(10):
            response = self.session.get(f"{self.base_url}/login")
            results.append(response.status_code)
            time.sleep(0.1)  # Small delay between requests
        
        # Check if rate limiting is working
        if 429 in results:
            self.test_results.append(("Rate Limiting", "PASS", "Rate limiting is working"))
            print(f"{Fore.GREEN}[+] Rate limiting is working{Style.RESET_ALL}")
        else:
            self.test_results.append(("Rate Limiting", "FAIL", "Rate limiting not detected"))
            print(f"{Fore.RED}[-] Rate limiting not detected{Style.RESET_ALL}")

    def test_xss_protection(self):
        """Test XSS protection"""
        print(f"\n{Fore.YELLOW}[*] Testing XSS Protection...{Style.RESET_ALL}")
        
        # Test payloads
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><script>alert("XSS")</script>'
        ]
        
        for payload in xss_payloads:
            # Test in URL parameter
            response = self.session.get(f"{self.base_url}/search?q={payload}")
            if payload in response.text:
                self.test_results.append(("XSS Protection", "FAIL", f"XSS vulnerability found with payload: {payload}"))
                print(f"{Fore.RED}[-] XSS vulnerability found with payload: {payload}{Style.RESET_ALL}")
                return
        
        self.test_results.append(("XSS Protection", "PASS", "No XSS vulnerabilities found"))
        print(f"{Fore.GREEN}[+] No XSS vulnerabilities found{Style.RESET_ALL}")

    def test_csrf_protection(self):
        """Test CSRF protection"""
        print(f"\n{Fore.YELLOW}[*] Testing CSRF Protection...{Style.RESET_ALL}")
        
        # Try to make a POST request without CSRF token
        response = self.session.post(
            f"{self.base_url}/update_profile",
            data={"name": "test"}
        )
        
        if response.status_code == 403:
            self.test_results.append(("CSRF Protection", "PASS", "CSRF protection is working"))
            print(f"{Fore.GREEN}[+] CSRF protection is working{Style.RESET_ALL}")
        else:
            self.test_results.append(("CSRF Protection", "FAIL", "CSRF protection not detected"))
            print(f"{Fore.RED}[-] CSRF protection not detected{Style.RESET_ALL}")

    def test_ssl_security(self):
        """Test SSL/TLS security"""
        print(f"\n{Fore.YELLOW}[*] Testing SSL/TLS Security...{Style.RESET_ALL}")
        
        try:
            response = requests.get(self.base_url, verify=True)
            if response.url.startswith('https'):
                self.test_results.append(("SSL/TLS", "PASS", "HTTPS is enforced"))
                print(f"{Fore.GREEN}[+] HTTPS is enforced{Style.RESET_ALL}")
            else:
                self.test_results.append(("SSL/TLS", "FAIL", "HTTPS not enforced"))
                print(f"{Fore.RED}[-] HTTPS not enforced{Style.RESET_ALL}")
        except requests.exceptions.SSLError:
            self.test_results.append(("SSL/TLS", "FAIL", "SSL certificate error"))
            print(f"{Fore.RED}[-] SSL certificate error{Style.RESET_ALL}")

    def test_security_headers(self):
        """Test security headers"""
        print(f"\n{Fore.YELLOW}[*] Testing Security Headers...{Style.RESET_ALL}")
        
        response = self.session.get(self.base_url)
        headers = response.headers
        
        required_headers = {
            'Content-Security-Policy': 'CSP header missing',
            'X-Content-Type-Options': 'Content type options header missing',
            'X-Frame-Options': 'Frame options header missing',
            'X-XSS-Protection': 'XSS protection header missing',
            'Strict-Transport-Security': 'HSTS header missing'
        }
        
        missing_headers = []
        for header, message in required_headers.items():
            if header not in headers:
                missing_headers.append(message)
        
        if missing_headers:
            self.test_results.append(("Security Headers", "FAIL", f"Missing headers: {', '.join(missing_headers)}"))
            print(f"{Fore.RED}[-] Missing security headers: {', '.join(missing_headers)}{Style.RESET_ALL}")
        else:
            self.test_results.append(("Security Headers", "PASS", "All required security headers present"))
            print(f"{Fore.GREEN}[+] All required security headers present{Style.RESET_ALL}")

    def test_brute_force_protection(self):
        """Test brute force protection"""
        print(f"\n{Fore.YELLOW}[*] Testing Brute Force Protection...{Style.RESET_ALL}")
        
        # Try multiple login attempts
        for i in range(5):
            response = self.session.post(
                f"{self.base_url}/login",
                data={
                    "username": f"test{i}",
                    "password": "wrongpassword"
                }
            )
            time.sleep(1)
        
        # Check if account lockout is triggered
        response = self.session.post(
            f"{self.base_url}/login",
            data={
                "username": "test0",
                "password": "wrongpassword"
            }
        )
        
        if "account locked" in response.text.lower() or response.status_code == 403:
            self.test_results.append(("Brute Force Protection", "PASS", "Account lockout is working"))
            print(f"{Fore.GREEN}[+] Account lockout is working{Style.RESET_ALL}")
        else:
            self.test_results.append(("Brute Force Protection", "FAIL", "Account lockout not detected"))
            print(f"{Fore.RED}[-] Account lockout not detected{Style.RESET_ALL}")

    def test_phishing_protection(self):
        """Test phishing protection measures"""
        print(f"\n{Fore.YELLOW}[*] Testing Phishing Protection...{Style.RESET_ALL}")
        
        # Get the website content
        response = self.session.get(self.base_url)
        content = response.text.lower()
        
        # Check for common phishing indicators
        phishing_indicators = {
            'suspicious_redirects': ['window.location', 'meta refresh', 'http-equiv="refresh"'],
            'fake_login_forms': ['login', 'signin', 'password', 'username'],
            'urgency_keywords': ['urgent', 'immediately', 'verify', 'confirm', 'update'],
            'spoofed_elements': ['paypal', 'bank', 'amazon', 'apple', 'microsoft']
        }
        
        found_indicators = []
        for category, indicators in phishing_indicators.items():
            for indicator in indicators:
                if indicator in content:
                    found_indicators.append(f"{category}: {indicator}")
        
        # Check email security headers
        email_headers = {
            'SPF': 'v=spf1',
            'DKIM': 'v=DKIM1',
            'DMARC': 'v=DMARC1'
        }
        
        # Check DNS records for email security
        try:
            domain = self.base_url.split('//')[-1].split('/')[0]
            dns_records = {
                'SPF': self.defenses.check_email_domain(f"test@{domain}"),
                'MX': len(dns.resolver.resolve(domain, 'MX')) > 0
            }
        except:
            dns_records = {'SPF': False, 'MX': False}
        
        # Evaluate results
        if found_indicators:
            self.test_results.append(("Phishing Protection", "FAIL", 
                f"Found potential phishing indicators: {', '.join(found_indicators)}"))
            print(f"{Fore.RED}[-] Found potential phishing indicators{Style.RESET_ALL}")
            for indicator in found_indicators:
                print(f"{Fore.RED}    - {indicator}{Style.RESET_ALL}")
        else:
            self.test_results.append(("Phishing Protection", "PASS", 
                "No obvious phishing indicators found"))
            print(f"{Fore.GREEN}[+] No obvious phishing indicators found{Style.RESET_ALL}")
        
        # Report email security status
        print(f"\n{Fore.CYAN}[*] Email Security Status:{Style.RESET_ALL}")
        for protocol, status in dns_records.items():
            color = Fore.GREEN if status else Fore.RED
            print(f"{protocol}: {color}{'Enabled' if status else 'Disabled'}{Style.RESET_ALL}")
        
        # Add email security to results
        email_security_status = "Email security: " + ", ".join(
            f"{k} {'enabled' if v else 'disabled'}" 
            for k, v in dns_records.items()
        )
        self.test_results.append(("Email Security", 
            "PASS" if all(dns_records.values()) else "FAIL", 
            email_security_status))

    def run_all_tests(self):
        """Run all security tests"""
        print(f"\n[*] Starting security tests for {self.base_url}")
        
        tests = [
            self.test_rate_limiting,
            self.test_xss_protection,
            self.test_csrf_protection,
            self.test_ssl_security,
            self.test_security_headers,
            self.test_brute_force_protection,
            self.test_phishing_protection
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"[!] Error during test: {str(e)}")
        
        self.print_results()

    def print_results(self):
        """Print test results summary"""
        print(f"\n{Fore.CYAN}[*] Test Results Summary:{Style.RESET_ALL}")
        print("-" * 80)
        print(f"{'Test':<30} {'Status':<10} {'Details':<40}")
        print("-" * 80)
        
        for test, status, details in self.test_results:
            color = Fore.GREEN if status == "PASS" else Fore.RED
            print(f"{test:<30} {color}{status:<10}{Style.RESET_ALL} {details:<40}")
        
        print("-" * 80)
        
        # Calculate pass/fail ratio
        total = len(self.test_results)
        passed = sum(1 for _, status, _ in self.test_results if status == "PASS")
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"Total Tests: {total}")
        print(f"Passed: {Fore.GREEN}{passed}{Style.RESET_ALL}")
        print(f"Failed: {Fore.RED}{total - passed}{Style.RESET_ALL}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")

def main():
    # Get website URL from user
    website_url = input("Enter website URL to test (e.g., https://example.com): ")
    
    # Create tester instance and run tests
    tester = SecurityTester(website_url)
    tester.run_all_tests()

if __name__ == "__main__":
    main() 