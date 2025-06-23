import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import Dict, List, Optional, Any
import os
import base64
from io import BytesIO
import re

class ReportGenerator:
    def __init__(self, company_name: str, company_logo: Optional[str] = None):
        """Initialize the report generator with company branding"""
        self.company_name = company_name
        self.company_logo = company_logo
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Color scheme for severity levels
        self.severity_colors = {
            "Critical": colors.red,
            "High": colors.orangered,
            "Medium": colors.orange,
            "Low": colors.gold
        }
        
        # OWASP Top 10 mapping
        self.owasp_mapping = {
            "SQL Injection": "A1:2021-Broken Access Control",
            "Command Injection": "A3:2021-Injection",
            "XSS": "A3:2021-Injection",
            "CSRF": "A1:2021-Broken Access Control",
            "Insecure Deserialization": "A8:2021-Software and Data Integrity Failures",
            "XXE": "A4:2021-Insecure Design",
            "SSRF": "A5:2021-Security Misconfiguration",
            "File Upload": "A1:2021-Broken Access Control",
            "Insecure Direct Object Reference": "A1:2021-Broken Access Control",
            "Security Misconfiguration": "A5:2021-Security Misconfiguration"
        }
        
        # Initialize styles
        self.styles = getSampleStyleSheet()
        
        # Add custom code style
        self.styles.add(ParagraphStyle(
            name='CodeStyle',
            fontName='Courier',
            fontSize=9,
            leading=12,
            spaceAfter=10
        ))
        
        # Modify existing styles
        self.styles['Heading1'].fontSize = 18
        self.styles['Heading1'].spaceAfter = 20
        self.styles['Heading1'].textColor = colors.HexColor('#1a1a1a')
        
        self.styles['Heading2'].fontSize = 14
        self.styles['Heading2'].spaceAfter = 15
        self.styles['Heading2'].textColor = colors.HexColor('#2a2a2a')
        
        # Add custom vulnerability styles
        self.styles.add(ParagraphStyle(
            name='VulnCritical',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.HexColor('#cc0000')
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnHigh',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.HexColor('#ff4500')
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnMedium',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.HexColor('#ff8c00')
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnLow',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.HexColor('#ffaa00')
        ))

    def strip_emojis(self, text: str) -> str:
        """Remove emojis and other special characters from text"""
        # Replace common emojis with text equivalents
        emoji_replacements = {
            "🔍": "[Search]",
            "🚨": "[Alert]",
            "⚠️": "[Warning]",
            "✅": "[Success]",
            "❌": "[Error]",
            "📋": "[Report]",
            "🔧": "[Debug]",
            "🏆": "[Trophy]",
            "💡": "[Info]",
            "🔥": "[Critical]"
        }
        
        for emoji, replacement in emoji_replacements.items():
            text = text.replace(emoji, replacement)
            
        # Remove any remaining emojis
        emoji_pattern = re.compile("["
            u"\U0001F600-\U0001F64F"  # emoticons
            u"\U0001F300-\U0001F5FF"  # symbols & pictographs
            u"\U0001F680-\U0001F6FF"  # transport & map symbols
            u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
            u"\U00002702-\U000027B0"
            u"\U000024C2-\U0001F251"
            "]+", flags=re.UNICODE)
        
        return emoji_pattern.sub('', text)

    def generate_executive_pdf(self, analysis_results: Dict[str, Any], output_path: str) -> str:
        """Generate a concise executive summary PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=72)
        
        story = []
        
        # Title
        story.append(Paragraph(f"{self.company_name}", self.styles['Heading1']))
        story.append(Paragraph(f"Executive Security Summary", self.styles['Heading2']))
        story.append(Paragraph(f"Generated: {self.timestamp}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Security Score
        score = analysis_results.get('security_score', 0)
        score_text = self.strip_emojis(f"Security Score: {score}/100")
        story.append(Paragraph(score_text, self.styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Key Findings
        story.append(Paragraph("Key Findings:", self.styles['Heading2']))
        for vuln in analysis_results.get('vulnerabilities', []):
            # Choose style based on severity
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                style = self.styles['VulnCritical']
            elif severity == 'High':
                style = self.styles['VulnHigh']
            elif severity == 'Medium':
                style = self.styles['VulnMedium']
            else:
                style = self.styles['VulnLow']
            
            text = self.strip_emojis(f"• {vuln['type']} ({severity})")
            story.append(Paragraph(text, style))
        
        story.append(Spacer(1, 20))
        
        # Overall Assessment
        story.append(Paragraph("Overall Assessment:", self.styles['Heading2']))
        assessment = self.strip_emojis(analysis_results.get('overall_assessment', ''))
        story.append(Paragraph(assessment, self.styles['Normal']))
        
        # Build the PDF
        doc.build(story)
        return output_path

    def generate_technical_pdf(self, analysis_results: Dict[str, Any], code: str, output_path: str) -> str:
        """Generate a detailed technical PDF report with code examples"""
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=72)
        
        story = []
        
        # Title
        story.append(Paragraph(f"{self.company_name}", self.styles['Heading1']))
        story.append(Paragraph(f"Technical Security Analysis", self.styles['Heading2']))
        story.append(Paragraph(f"Generated: {self.timestamp}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Security Score
        score = analysis_results.get('security_score', 0)
        score_text = self.strip_emojis(f"Security Score: {score}/100")
        story.append(Paragraph(score_text, self.styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings:", self.styles['Heading2']))
        
        for vuln in analysis_results.get('vulnerabilities', []):
            # Choose style based on severity
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                style = self.styles['VulnCritical']
            elif severity == 'High':
                style = self.styles['VulnHigh']
            elif severity == 'Medium':
                style = self.styles['VulnMedium']
            else:
                style = self.styles['VulnLow']
            
            # Vulnerability header
            header = self.strip_emojis(f"• {vuln['type']} ({severity})")
            story.append(Paragraph(header, style))
            
            # Vulnerability details
            details = [
                f"<b>Line:</b> {vuln.get('line', 'N/A')}",
                f"<b>Description:</b> {self.strip_emojis(vuln.get('description', 'N/A'))}",
                f"<b>Explanation:</b> {self.strip_emojis(vuln.get('explanation', 'N/A'))}",
                f"<b>Fix:</b> {self.strip_emojis(vuln.get('fix', 'N/A'))}",
                f"<b>CWE:</b> {vuln.get('cwe', 'N/A')}"
            ]
            
            for detail in details:
                story.append(Paragraph(detail, self.styles['Normal']))
            
            story.append(Spacer(1, 10))
        
        # Code Analysis
        story.append(Paragraph("Code Analysis:", self.styles['Heading2']))
        
        # Process code line by line
        code_lines = code.split('\n')
        for line in code_lines:
            # Clean the line of any problematic characters
            clean_line = self.strip_emojis(line)
            # Replace tabs with spaces for consistent formatting
            clean_line = clean_line.replace('\t', '    ')
            # Escape special characters for PDF
            clean_line = clean_line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            story.append(Paragraph(clean_line, self.styles['CodeStyle']))
        
        # Build the PDF
        doc.build(story)
        return output_path

    def generate_html_report(self, analysis_results: Dict[str, Any], code: str) -> str:
        """Generate an interactive HTML report"""
        # Create vulnerability distribution chart
        vuln_chart = self._create_vulnerability_chart(analysis_results)
        
        # Create risk matrix
        risk_matrix = self._create_risk_matrix(analysis_results)
        
        # Generate HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Analysis Report</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .section {{ margin: 20px 0; }}
                .vulnerability {{ 
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                }}
                .critical {{ border-left: 5px solid #ff0000; }}
                .high {{ border-left: 5px solid #ff4500; }}
                .medium {{ border-left: 5px solid #ffa500; }}
                .low {{ border-left: 5px solid #ffd700; }}
                pre {{ 
                    background-color: #f5f5f5;
                    padding: 15px;
                    border-radius: 5px;
                    overflow-x: auto;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{self.company_name}</h1>
                <p>Security Analysis Report - {self.timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Security Score: {analysis_results.get('security_score', 0)}/100</h2>
                <div id="vulnChart"></div>
                <div id="riskMatrix"></div>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {self._generate_vulnerability_html(analysis_results)}
            </div>
            
            <div class="section">
                <h2>Code Analysis</h2>
                <pre>{code}</pre>
            </div>
            
            <script>
                {vuln_chart}
                {risk_matrix}
            </script>
        </body>
        </html>
        """
        
        return html_content

    def _generate_vulnerability_html(self, analysis_results: Dict[str, Any]) -> str:
        """Generate HTML for vulnerabilities section"""
        vuln_html = ""
        for vuln in analysis_results.get('vulnerabilities', []):
            severity_class = vuln['severity'].lower()
            vuln_html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln['type']} ({vuln['severity']})</h3>
                <p><strong>Line:</strong> {vuln.get('line', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                <p><strong>Explanation:</strong> {vuln.get('explanation', 'N/A')}</p>
                <p><strong>Fix:</strong> {vuln.get('fix', 'N/A')}</p>
                <p><strong>CWE:</strong> {vuln.get('cwe', 'N/A')}</p>
            </div>
            """
        return vuln_html

    def _create_vulnerability_chart(self, analysis_results: Dict[str, Any]) -> str:
        """Create a vulnerability distribution chart using Plotly"""
        vuln_data = {}
        for vuln in analysis_results.get('vulnerabilities', []):
            severity = vuln['severity']
            vuln_data[severity] = vuln_data.get(severity, 0) + 1
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(vuln_data.keys()),
                y=list(vuln_data.values()),
                marker_color=['#ff0000', '#ff4500', '#ffa500', '#ffd700']
            )
        ])
        
        fig.update_layout(
            title="Vulnerability Distribution by Severity",
            xaxis_title="Severity",
            yaxis_title="Count"
        )
        
        return f"Plotly.newPlot('vulnChart', {fig.to_json()})"

    def _create_risk_matrix(self, analysis_results: Dict[str, Any]) -> str:
        """Create a risk matrix visualization"""
        # Create a simple risk matrix
        matrix_data = {
            'Critical': [1, 0, 0, 0],
            'High': [0, 2, 0, 0],
            'Medium': [0, 0, 3, 0],
            'Low': [0, 0, 0, 4]
        }
        
        fig = go.Figure(data=[
            go.Heatmap(
                z=[matrix_data[severity] for severity in ['Critical', 'High', 'Medium', 'Low']],
                x=['Very High', 'High', 'Medium', 'Low'],
                y=['Critical', 'High', 'Medium', 'Low'],
                colorscale='Reds'
            )
        ])
        
        fig.update_layout(
            title="Risk Matrix",
            xaxis_title="Impact",
            yaxis_title="Likelihood"
        )
        
        return f"Plotly.newPlot('riskMatrix', {fig.to_json()})"
