from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import json
import os
from datetime import datetime
from typing import Dict


class ReportGenerator:
    def __init__(self, scan_results: Dict):
        self.scan_results = scan_results
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_html_report(self) -> str:
        """HTML formatida hisobot yaratish"""
        template = """
        <!DOCTYPE html>
        <html lang="uz">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Pentest Hisoboti - {{ scan_results.target_url }}</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background: #f5f5f5;
                    padding: 20px;
                }
                
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #e74c3c;
                }
                
                .header h1 {
                    color: #2c3e50;
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }
                
                .summary-box {
                    background: #ecf0f1;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }
                
                .risk-level {
                    font-size: 1.2em;
                    font-weight: bold;
                    padding: 10px;
                    border-radius: 5px;
                    display: inline-block;
                }
                
                .risk-critical { background: #e74c3c; color: white; }
                .risk-high { background: #e67e22; color: white; }
                .risk-medium { background: #f39c12; color: white; }
                .risk-low { background: #3498db; color: white; }
                .risk-info { background: #95a5a6; color: white; }
                
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                
                .stat-card {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    text-align: center;
                }
                
                .stat-value {
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #2c3e50;
                }
                
                .vulnerability-card {
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    overflow: hidden;
                }
                
                .vuln-header {
                    padding: 15px;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .vuln-critical { background: #fdeaea; border-left: 5px solid #e74c3c; }
                .vuln-high { background: #fef5e7; border-left: 5px solid #e67e22; }
                .vuln-medium { background: #fef9e7; border-left: 5px solid #f39c12; }
                .vuln-low { background: #e8f4fd; border-left: 5px solid #3498db; }
                
                .vuln-content {
                    padding: 20px;
                    background: white;
                    display: none;
                }
                
                .vuln-content.active {
                    display: block;
                }
                
                .severity-badge {
                    padding: 5px 10px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }
                
                .remediation-box {
                    background: #e8f8f5;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 15px;
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                
                th {
                    background: #34495e;
                    color: white;
                }
                
                tr:hover {
                    background: #f5f5f5;
                }
                
                .footer {
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #7f8c8d;
                }
                
                .btn {
                    background: #3498db;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 1em;
                }
                
                .btn:hover {
                    background: #2980b9;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 AI Pentest Hisoboti</h1>
                    <p>Yaratilgan: {{ scan_results.scan_completed }}</p>
                </div>
                
                <div class="summary-box">
                    <h2>📊 Umumiy ma'lumot</h2>
                    <p><strong>URL:</strong> {{ scan_results.target_url }}</p>
                    <p><strong>Status kod:</strong> {{ scan_results.status_code }}</p>
                    <p><strong>Skanerlash vaqti:</strong> {{ scan_results.scan_duration }} soniya</p>
                    
                    <div class="risk-level risk-{{ scan_results.summary.risk_level.lower() }}">
                        Xavf darajasi: {{ scan_results.summary.risk_level }}
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{{ scan_results.summary.total_vulnerabilities }}</div>
                        <div>Jami zaifliklar</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ scan_results.summary.severity_counts.critical }}</div>
                        <div>Critical</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ scan_results.summary.severity_counts.high }}</div>
                        <div>High</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ scan_results.summary.severity_counts.medium }}</div>
                        <div>Medium</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ scan_results.summary.severity_counts.low }}</div>
                        <div>Low</div>
                    </div>
                </div>
                
                <h2>🔍 Aniqlangan zaifliklar</h2>
                
                {% for vuln in scan_results.vulnerabilities %}
                <div class="vulnerability-card">
                    <div class="vuln-header vuln-{{ vuln.severity }}" onclick="toggleVuln(this)">
                        <div>
                            <strong>{{ vuln.type }}</strong>
                            <p>{{ vuln.description }}</p>
                        </div>
                        <span class="severity-badge" style="background: {% if vuln.severity == 'critical' %}#e74c3c{% elif vuln.severity == 'high' %}#e67e22{% elif vuln.severity == 'medium' %}#f39c12{% else %}#3498db{% endif %}; color: white;">
                            {{ vuln.severity|upper }}
                        </span>
                    </div>
                    <div class="vuln-content">
                        <h4>📝 Tafsilotlar</h4>
                        {% if vuln.details %}
                        <pre>{{ vuln.details }}</pre>
                        {% endif %}
                        
                        <div class="remediation-box">
                            <h4>🔧 Remediation</h4>
                            <p>{{ vuln.remediation }}</p>
                        </div>
                        
                        {% if vuln.ai_analysis %}
                        <h4>🤖 AI tahlili</h4>
                        <p><strong>Impact score:</strong> {{ vuln.ai_analysis.impact_score }}</p>
                        <p><strong>Exploit difficulty:</strong> {{ vuln.ai_analysis.exploit_difficulty }}</p>
                        <p><strong>Priority:</strong> {{ vuln.ai_analysis.priority }}</p>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                
                {% if scan_results.information %}
                <h2>ℹ️ Qo'shimcha ma'lumotlar</h2>
                <table>
                    <tr>
                        <th>Texnologiya</th>
                        <th>Versiya</th>
                    </tr>
                    {% for tech in scan_results.technologies %}
                    <tr>
                        <td>{{ tech.name }}</td>
                        <td>{{ tech.version if tech.version else 'Noma\'lum' }}</td>
                    </tr>
                    {% endfor %}
                </table>
                
                {% if scan_results.information.emails %}
                <h3>📧 Topilgan email manzillar</h3>
                <ul>
                    {% for email in scan_results.information.emails %}
                    <li>{{ email }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                {% endif %}
                
                {% if scan_results.ai_enhanced %}
                <h2>🧠 AI tahlili</h2>
                
                <h3>Xavf bashorati</h3>
                <p><strong>Daraja:</strong> {{ scan_results.ai_enhanced.ai_risk_prediction.level|upper }}</p>
                <p><strong>Ishonchlilik:</strong> {{ (scan_results.ai_enhanced.ai_risk_prediction.confidence * 100)|int }}%</p>
                <p><strong>Xavf balli:</strong> {{ scan_results.ai_enhanced.ai_risk_prediction.score }}/100</p>
                
                <h3>Remediation takliflari</h3>
                {% for remediation in scan_results.ai_enhanced.ai_remediation %}
                <div class="remediation-box">
                    <h4>{{ remediation.title }}</h4>
                    <p><strong>Vulnerability:</strong> {{ remediation.vulnerability }}</p>
                    <p><strong>Priority:</strong> {{ remediation.priority }}</p>
                    <ol>
                        {% for step in remediation.steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ol>
                </div>
                {% endfor %}
                {% endif %}
                
                <div class="footer">
                    <p>© 2024 AI Pentest System | Ushbu hisobot avtomatik ravishda yaratildi</p>
                    <p>⚠️ Diqqat: Bu hisobot faqat ma'lumot uchun. Haqiqiy xavfsizlik auditi uchun mutaxassislarga murojaat qiling.</p>
                </div>
            </div>
            
            <script>
                function toggleVuln(element) {
                    const content = element.nextElementSibling;
                    content.classList.toggle('active');
                }
                
                function downloadReport() {
                    const reportContent = document.documentElement.outerHTML;
                    const blob = new Blob([reportContent], { type: 'text/html' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'pentest-report.html';
                    a.click();
                }
            </script>
        </body>
        </html>
        """
        
        template_obj = Template(template)
        html_content = template_obj.render(scan_results=self.scan_results)
        
        # Hisobotni saqlash
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.report_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def generate_pdf_report(self) -> str:
        """PDF formatida hisobot yaratish"""
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.report_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Sarlavha
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30
        )
        
        title = Paragraph(f"AI Pentest Hisoboti", title_style)
        story.append(title)
        
        # URL ma'lumoti
        url_text = f"<b>URL:</b> {self.scan_results.get('target_url', '')}<br/>"
        url_text += f"<b>Skanerlangan:</b> {self.scan_results.get('scan_completed', '')}"
        story.append(Paragraph(url_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Xulosa
        summary = self.scan_results.get('summary', {})
        summary_text = f"<b>Jami zaifliklar:</b> {summary.get('total_vulnerabilities', 0)}<br/>"
        story.append(Paragraph(summary_text, styles['Normal']))
        
        # Zaifliklar jadvali
        data = [['Zaiflik turi', 'Severity', 'Remediation']]
        for vuln in self.scan_results.get('vulnerabilities', [])[:10]:  # Eng ko'pi bilan 10 ta
            data.append([
                vuln.get('type', ''),
                vuln.get('severity', ''),
                vuln.get('remediation', '')[:50] + '...'
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        
        # PDF yaratish
        doc.build(story)
        
        return filepath
    
    def generate_json_report(self) -> str:
        """JSON formatida hisobot yaratish"""
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.report_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_markdown_report(self) -> str:
        """Markdown formatida hisobot yaratish"""
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.report_dir, filename)
        
        md_content = f"""# AI Pentest Hisoboti

## Umumiy ma'lumot
- **URL:** {self.scan_results.get('target_url', '')}
- **Skanerlangan:** {self.scan_results.get('scan_completed', '')}
- **Skanerlash vaqti:** {self.scan_results.get('scan_duration', '')} soniya

## Xulosa
- **Jami zaifliklar:** {self.scan_results.get('summary', {}).get('total_vulnerabilities', 0)}
- **Xavf darajasi:** {self.scan_results.get('summary', {}).get('risk_level', 'N/A')}

## Aniqlangan zaifliklar

"""
        
        for vuln in self.scan_results.get('vulnerabilities', []):
            md_content += f"""
### {vuln.get('type', '')} (Severity: {vuln.get('severity', '').upper()})
- **Tavsif:** {vuln.get('description', '')}
- **Remediation:** {vuln.get('remediation', '')}

"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return filepath