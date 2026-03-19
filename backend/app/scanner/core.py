import aiohttp
import asyncio
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import re
import ssl
import socket
from datetime import datetime
import json

class WebScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'url': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'information': {},
            'headers': {},
            'technologies': []
        }
    
    async def scan_async(self):
        """Asinxron skanerlash"""
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.check_ssl(session),
                self.check_headers(session),
                self.check_robots_txt(session),
                self.check_sitemap(session),
                self.check_forms(session)
            ]
            await asyncio.gather(*tasks)
    
    def scan_sync(self):
        """Sinxron skanerlash"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            
            # Texnologiyalarni aniqlash
            self.detect_technologies(response)
            
            # Xavfsizlik headerlarini tekshirish
            self.check_security_headers(response)
            
            # Formlarni tekshirish
            self.check_forms_sync(response)
            
            # XSS zaifliklarini tekshirish
            self.check_xss_vulnerabilities(response)
            
            # SQL Injection tekshirish
            self.check_sql_injection()
            
            # Foydali ma'lumotlarni yig'ish
            self.gather_info(response)
            
        except requests.exceptions.RequestException as e:
            self.results['error'] = str(e)
        
        return self.results
    
    def detect_technologies(self, response):
        """Veb texnologiyalarni aniqlash"""
        headers = response.headers
        html_content = response.text.lower()
        
        technologies = []
        
        # Server texnologiyasi
        if 'server' in headers:
            technologies.append({'name': 'Server', 'version': headers['server']})
        
        # CMS aniqlash
        if 'wp-content' in html_content or 'wp-includes' in html_content:
            technologies.append({'name': 'WordPress', 'certainty': 'high'})
        elif 'drupal' in html_content:
            technologies.append({'name': 'Drupal', 'certainty': 'medium'})
        elif 'joomla' in html_content:
            technologies.append({'name': 'Joomla', 'certainty': 'medium'})
        
        # JavaScript frameworklar
        if 'react' in html_content or 'reactjs' in html_content:
            technologies.append({'name': 'React', 'certainty': 'medium'})
        if 'vue' in html_content:
            technologies.append({'name': 'Vue.js', 'certainty': 'medium'})
        if 'angular' in html_content:
            technologies.append({'name': 'Angular', 'certainty': 'medium'})
        
        self.results['technologies'] = technologies
    
    def check_security_headers(self, response):
        """Xavfsizlik headerlarini tekshirish"""
        headers = response.headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking himoyasi',
            'X-Content-Type-Options': 'MIME sniffing himoyasi',
            'X-XSS-Protection': 'XSS himoyasi',
            'Content-Security-Policy': 'CSP himoyasi',
            'Strict-Transport-Security': 'HSTS himoyasi',
            'Referrer-Policy': 'Referrer himoyasi'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in headers:
                missing_headers.append({
                    'header': header,
                    'description': description,
                    'severity': 'medium' if header != 'Content-Security-Policy' else 'high'
                })
        
        if missing_headers:
            self.results['vulnerabilities'].append({
                'type': 'Missing Security Headers',
                'description': 'Muhim xavfsizlik headerlari mavjud emas',
                'details': missing_headers,
                'severity': 'medium',
                'remediation': 'Quyidagi headerlarni qo\'shing: ' + ', '.join([h['header'] for h in missing_headers])
            })
    
    def check_forms_sync(self, response):
        """Formlarni tekshirish"""
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        form_issues = []
        for form in forms:
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            inputs = form.find_all('input')
            for input_field in inputs:
                input_type = input_field.get('type', 'text')
                input_name = input_field.get('name', '')
                
                # Xavfsizlik tekshiruvlari
                if input_type == 'password' and not form.get('method', '').upper() == 'POST':
                    form_issues.append({
                        'type': 'Insecure Form Method',
                        'field': input_name,
                        'description': 'Parol sohasi GET metodi bilan yuborilmoqda',
                        'severity': 'high'
                    })
                
                # CSRF token tekshiruvi
                if input_type == 'hidden' and 'csrf' in input_name.lower():
                    form_info['has_csrf'] = True
                
                form_info['inputs'].append({
                    'name': input_name,
                    'type': input_type
                })
            
            if not form_info.get('has_csrf', False):
                form_issues.append({
                    'type': 'Missing CSRF Token',
                    'form_action': form_info['action'],
                    'description': 'Formada CSRF token mavjud emas',
                    'severity': 'medium'
                })
        
        if form_issues:
            self.results['vulnerabilities'].extend(form_issues)
        
        self.results['forms'] = forms_count = len(forms)
    
    def check_xss_vulnerabilities(self, response):
        """XSS zaifliklarini tekshirish"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # XSS payloadlari
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            'onerror=alert("XSS")',
            'onload=alert("XSS")'
        ]
        
        # URL parametrlarini tekshirish
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            params = parsed_url.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    # Parametr qiymati sahifada aks etayotganini tekshirish
                    if value and value in response.text:
                        self.results['vulnerabilities'].append({
                            'type': 'Possible XSS',
                            'parameter': key,
                            'description': f'"{key}" parametri sahifada aks etmoqda, XSS xavfi mavjud',
                            'severity': 'medium',
                            'remediation': 'Parametr qiymatlarini tozalang (escape qiling)'
                        })
        
        # Inline skriptlarni tekshirish
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and any(payload in script.string for payload in ['document.cookie', 'localStorage', 'sessionStorage']):
                self.results['vulnerabilities'].append({
                    'type': 'Sensitive Data Exposure',
                    'description': 'Skriptda sezgir ma\'lumotlar (cookie, localStorage) mavjud',
                    'severity': 'medium',
                    'remediation': 'Sezgir ma\'lumotlarni skriptlarda saqlamang'
                })
    
    def check_sql_injection(self):
        """SQL Injection zaifliklarini tekshirish"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "' OR '1'='1'/*",
            "admin'--"
        ]
        
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            for payload in sql_payloads:
                try:
                    # Har bir parametrga payload qo'shib tekshirish
                    test_url = f"{base_url}?id={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # SQL xatoliklarini aniqlash
                    sql_errors = [
                        "mysql_fetch",
                        "sqlite",
                        "SQL syntax",
                        "mysql_error",
                        "ORA-",
                        "PostgreSQL",
                        "SQL Server",
                        "Unclosed quotation mark"
                    ]
                    
                    if any(error in response.text for error in sql_errors):
                        self.results['vulnerabilities'].append({
                            'type': 'SQL Injection',
                            'payload': payload,
                            'description': 'SQL Injection zaifligi aniqlandi',
                            'severity': 'critical',
                            'remediation': 'Parametrli so\'rovlar (prepared statements) ishlating'
                        })
                        break
                        
                except:
                    continue
    
    def gather_info(self, response):
        """Foydali ma'lumotlarni yig'ish"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Email manzillarni topish
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
        if emails:
            self.results['information']['emails'] = list(set(emails))
        
        # Kommentariyalarni tekshirish
        comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
        sensitive_comments = []
        for comment in comments:
            if any(word in comment.lower() for word in ['todo', 'fixme', 'password', 'username', 'admin', 'config']):
                sensitive_comments.append(comment.strip())
        
        if sensitive_comments:
            self.results['vulnerabilities'].append({
                'type': 'Sensitive Comments',
                'description': 'Sahifada sezgir kommentariyalar mavjud',
                'details': sensitive_comments[:5],
                'severity': 'low',
                'remediation': 'Kommentariyalarni olib tashlang'
            })
        
        # Ichki havolalarni aniqlash
        internal_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('/') or self.target_url in href:
                internal_links.append(href)
        
        self.results['information']['internal_links'] = len(internal_links)
    
    async def check_ssl(self, session):
        """SSL sertifikatini tekshirish"""
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.netloc or parsed_url.path
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Sertifikat muddatini tekshirish
                    not_after = cert['notAfter']
                    not_before = cert['notBefore']
                    
                    self.results['information']['ssl_cert'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': not_after,
                        'valid_from': not_before
                    }
        except Exception as e:
            self.results['vulnerabilities'].append({
                'type': 'SSL/TLS Issues',
                'description': f'SSL sertifikati tekshiruvida xatolik: {str(e)}',
                'severity': 'high'
            })
    
    async def check_headers(self, session):
        pass
    
    async def check_robots_txt(self, session):
        """robots.txt faylini tekshirish"""
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self.results['information']['robots_txt'] = {
                        'exists': True,
                        'content': content[:500]  # Birinchi 500 belgi
                    }
                    
                    # Maxfiy yo'llarni aniqlash
                    if 'Disallow' in content:
                        self.results['vulnerabilities'].append({
                            'type': 'Information Disclosure',
                            'description': 'robots.txt faylida maxfiy yo\'llar mavjud',
                            'severity': 'low',
                            'remediation': 'Maxfiy yo\'llarni robots.txt da ko\'rsatmang'
                        })
        except:
            pass
    
    async def check_sitemap(self, session):
        """sitemap.xml faylini tekshirish"""
        sitemap_url = urljoin(self.target_url, '/sitemap.xml')
        try:
            async with session.get(sitemap_url) as response:
                if response.status == 200:
                    self.results['information']['sitemap'] = {'exists': True}
        except:
            pass
    
    async def check_forms(self, session):
        pass
    
    def generate_summary(self):
        """Natijalar umumlashtirish"""
        vulnerabilities = self.results.get('vulnerabilities', [])
        
        severity_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            if severity in severity_count:
                severity_count[severity] += 1
        
        self.results['summary'] = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_count,
            'scan_url': self.target_url,
            'risk_level': self.calculate_risk_level(severity_count)
        }
        
        return self.results['summary']
    
    def calculate_risk_level(self, severity_count):
        """Xavf darajasini hisoblash"""
        if severity_count['critical'] > 0:
            return 'CRITICAL'
        elif severity_count['high'] > 2:
            return 'HIGH'
        elif severity_count['high'] > 0 or severity_count['medium'] > 3:
            return 'MEDIUM'
        elif severity_count['medium'] > 0 or severity_count['low'] > 5:
            return 'LOW'
        else:
            return 'INFO'