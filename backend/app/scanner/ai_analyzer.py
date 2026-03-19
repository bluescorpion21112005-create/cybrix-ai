import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import json
import re
from typing import Dict, List, Any
import asyncio

class AIAnalyzer:
    def __init__(self):
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.load_model()
    
    def load_model(self):
        """ML modelini yuklash"""
        try:
            self.model = joblib.load('models/vulnerability_model.pkl')
        except:
            # Model mavjud bo'lmasa, yangisini yaratish
            self.model = RandomForestClassifier(n_estimators=100)
    
    async def analyze_vulnerabilities(self, scan_results: Dict) -> Dict:
        """AI yordamida zaifliklarni tahlil qilish"""
        enhanced_results = scan_results.copy()
        
        # Zaifliklarni tasniflash
        vulnerabilities = enhanced_results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            # Har bir zaiflik uchun AI tahlili
            ai_analysis = await self.analyze_single_vulnerability(vuln)
            vuln['ai_analysis'] = ai_analysis
        
        # Umumiy xavf tahlili
        risk_prediction = await self.predict_risk_level(enhanced_results)
        enhanced_results['ai_risk_prediction'] = risk_prediction
        
        # Remediation takliflari
        remediation_suggestions = await self.generate_remediation_suggestions(vulnerabilities)
        enhanced_results['ai_remediation'] = remediation_suggestions
        
        return enhanced_results
    
    async def analyze_single_vulnerability(self, vulnerability: Dict) -> Dict:
        """Bitta zaiflikni chuqur tahlil qilish"""
        vuln_type = vulnerability.get('type', '')
        description = vulnerability.get('description', '')
        
        # Zaiflikning potentsial ta'sirini baholash
        impact_score = self.calculate_impact_score(vuln_type, description)
        
        # Ekspluatatsiya qilish qiyinligi
        exploit_difficulty = self.assess_exploit_difficulty(vuln_type)
        
        # Avtomatik ekspluatatsiya imkoniyati
        auto_exploitable = self.check_auto_exploitable(vuln_type)
        
        return {
            'impact_score': impact_score,
            'exploit_difficulty': exploit_difficulty,
            'auto_exploitable': auto_exploitable,
            'priority': self.calculate_priority(impact_score, exploit_difficulty),
            'cve_matches': await self.find_cve_matches(vuln_type, description)
        }
    
    def calculate_impact_score(self, vuln_type: str, description: str) -> float:
        """Zaiflik ta'sir darajasini hisoblash"""
        impact_keywords = {
            'critical': ['rce', 'remote code', 'sql injection', 'authentication bypass'],
            'high': ['xss', 'csrf', 'file upload', 'privilege escalation'],
            'medium': ['information disclosure', 'session fixation', 'directory listing'],
            'low': ['clickjacking', 'missing header', 'verbose error']
        }
        
        score = 5.0  # O'rtacha boshlang'ich ball
        
        text = f"{vuln_type} {description}".lower()
        
        for level, keywords in impact_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    if level == 'critical':
                        score = 9.0
                    elif level == 'high':
                        score = max(score, 7.0)
                    elif level == 'medium':
                        score = max(score, 5.0)
                    elif level == 'low':
                        score = max(score, 3.0)
        
        return round(score, 1)
    
    def assess_exploit_difficulty(self, vuln_type: str) -> str:
        """Ekspluatatsiya qilish qiyinligini baholash"""
        easy_exploits = ['xss', 'csrf', 'directory traversal', 'information disclosure']
        medium_exploits = ['sql injection', 'file upload', 'session fixation']
        hard_exploits = ['rce', 'buffer overflow', 'deserialization']
        
        vuln_type_lower = vuln_type.lower()
        
        for exploit in easy_exploits:
            if exploit in vuln_type_lower:
                return 'easy'
        
        for exploit in medium_exploits:
            if exploit in vuln_type_lower:
                return 'medium'
        
        for exploit in hard_exploits:
            if exploit in vuln_type_lower:
                return 'hard'
        
        return 'unknown'
    
    def check_auto_exploitable(self, vuln_type: str) -> bool:
        """Avtomatik ekspluatatsiya qilish imkoniyatini tekshirish"""
        auto_exploitable_types = ['sql injection', 'xss', 'csrf', 'directory listing']
        
        for exploit_type in auto_exploitable_types:
            if exploit_type in vuln_type.lower():
                return True
        
        return False
    
    def calculate_priority(self, impact_score: float, difficulty: str) -> str:
        """Prioritetni hisoblash"""
        difficulty_score = {'easy': 3, 'medium': 2, 'hard': 1, 'unknown': 1}
        
        total_score = impact_score * difficulty_score.get(difficulty, 1)
        
        if total_score >= 20:
            return 'critical'
        elif total_score >= 15:
            return 'high'
        elif total_score >= 10:
            return 'medium'
        else:
            return 'low'
    
    async def find_cve_matches(self, vuln_type: str, description: str) -> List[Dict]:
        """CVE ma'lumotlar bazasidan mosliklarni qidirish"""
        # Bu yerda CVE ma'lumotlar bazasiga so'rov yuborish mumkin
        # Hozircha namuna sifatida
        cve_matches = []
        
        common_cves = {
            'sql injection': ['CVE-2023-1234', 'CVE-2022-5678'],
            'xss': ['CVE-2023-4321', 'CVE-2022-8765'],
            'csrf': ['CVE-2023-9876']
        }
        
        for key, cves in common_cves.items():
            if key in vuln_type.lower():
                cve_matches.extend([{'id': cve, 'confidence': 'medium'} for cve in cves])
        
        return cve_matches[:3]  # Eng ko'pi bilan 3 ta
    
    async def predict_risk_level(self, scan_results: Dict) -> Dict:
        """Umumiy xavf darajasini bashorat qilish"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return {'level': 'safe', 'confidence': 0.95}
        
        # Xavf ballini hisoblash
        risk_score = 0
        vuln_count = len(vulnerabilities)
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            risk_score += severity_weights.get(severity, 0)
        
        # Normalizatsiya
        max_possible_score = vuln_count * 10
        if max_possible_score > 0:
            normalized_score = (risk_score / max_possible_score) * 100
        else:
            normalized_score = 0
        
        # Xavf darajasini aniqlash
        if normalized_score >= 70:
            level = 'critical'
            confidence = 0.85
        elif normalized_score >= 50:
            level = 'high'
            confidence = 0.80
        elif normalized_score >= 30:
            level = 'medium'
            confidence = 0.75
        elif normalized_score >= 10:
            level = 'low'
            confidence = 0.70
        else:
            level = 'info'
            confidence = 0.90
        
        return {
            'level': level,
            'score': round(normalized_score, 2),
            'confidence': confidence,
            'vulnerability_count': vuln_count
        }
    
    async def generate_remediation_suggestions(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remediation takliflarini yaratish"""
        suggestions = []
        
        remediation_templates = {
            'sql injection': {
                'title': 'SQL Injection himoyasini kuchaytirish',
                'steps': [
                    'Prepared statements yoki parametrli so\'rovlardan foydalaning',
                    'Foydalanuvchi kiritgan ma\'lumotlarni tozalang',
                    'ORM (Object-Relational Mapping) dan foydalaning',
                    'Ma\'lumotlar bazasi privilegiyalarini cheklang'
                ],
                'priority': 'high'
            },
            'xss': {
                'title': 'XSS himoyasini o\'rnatish',
                'steps': [
                    'Foydalanuvchi kiritgan ma\'lumotlarni escape qiling',
                    'Content Security Policy (CSP) headerini qo\'shing',
                    'X-XSS-Protection headerini yoqing',
                    'Input validatsiyasini kuchaytiring'
                ],
                'priority': 'high'
            },
            'csrf': {
                'title': 'CSRF himoyasini qo\'shish',
                'steps': [
                    'CSRF tokenlaridan foydalaning',
                    'SameSite cookie atributini qo\'shing',
                    'Muhim amallar uchun qayta autentifikatsiyani talab qiling',
                    'GET so\'rovlarida o\'zgarishlar qilmang'
                ],
                'priority': 'medium'
            },
            'missing headers': {
                'title': 'Xavfsizlik headerlarini qo\'shish',
                'steps': [
                    'X-Frame-Options: DENY headerini qo\'shing',
                    'X-Content-Type-Options: nosniff headerini qo\'shing',
                    'Strict-Transport-Security headerini qo\'shing',
                    'Referrer-Policy headerini sozlang'
                ],
                'priority': 'medium'
            }
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            
            for key, template in remediation_templates.items():
                if key in vuln_type:
                    suggestions.append({
                        'vulnerability': vuln.get('type'),
                        'remediation': template['title'],
                        'steps': template['steps'],
                        'priority': template['priority']
                    })
                    break
        
        return suggestions