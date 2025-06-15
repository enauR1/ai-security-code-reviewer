import json
from datetime import datetime
from fpdf import FPDF
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import Dict, List, Optional, Any
import os
import base64
from io import BytesIO

class ReportGenerator:
    def __init__(self, company_name: str, company_logo: Optional[str] = None):
        """Initialize the report generator with company branding"""
        self.company_name = company_name
        self.company_logo = company_logo
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Color scheme for severity levels
        self.severity_colors = {
            "Critical": (255, 0, 0),    # Red
            "High": (255, 69, 0),       # Orange-Red
            "Medium": (255, 165, 0),    # Orange
            "Low": (255, 215, 0)        # Gold
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
    
    def generate_executive_pdf(self, analysis_results: Dict[str, Any], output_path: str) -> str:
        """Generate a concise executive summary PDF report"""
        pdf = FPDF()
        pdf.add_page()
        
        # Set margins and font
        pdf.set_margins(20, 20, 20)
        pdf.set_auto_page_break(auto=True, margin=20)
        
        # Add header
        self._add_header(pdf, "Executive Security Summary")
        
        # Security Score
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"Security Score: {analysis_results.get('security_score', 0)}/100", ln=True)
        pdf.ln(5)
        
        # Key Findings
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Key Findings:", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        for vuln in analysis_results.get('vulnerabilities', []):
            # Ensure text fits within page width
            text = f"- {vuln['type']} ({vuln['severity']})"
            if pdf.get_string_width(text) > pdf.w - 40:  # Account for margins
                text = text[:int(len(text) * 0.8)] + "..."
            pdf.cell(0, 10, text, ln=True)
        
        pdf.ln(5)
        
        # Overall Assessment
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Overall Assessment:", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 12)
        assessment = analysis_results.get('overall_assessment', '')
        # Split long text into multiple lines
        for line in self._wrap_text(assessment, pdf.w - 40):
            pdf.cell(0, 10, line, ln=True)
        
        # Save the report
        pdf.output(output_path)
        return output_path
    
    def generate_technical_pdf(self, analysis_results: Dict[str, Any], code: str, output_path: str) -> str:
        """Generate a detailed technical PDF report with code examples"""
        pdf = FPDF()
        pdf.add_page()
        
        # Set margins and font
        pdf.set_margins(20, 20, 20)
        pdf.set_auto_page_break(auto=True, margin=20)
        
        # Add header
        self._add_header(pdf, "Technical Security Analysis")
        
        # Security Score
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, f"Security Score: {analysis_results.get('security_score', 0)}/100", ln=True)
        pdf.ln(5)
        
        # Detailed Findings
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Detailed Findings:", ln=True)
        pdf.ln(5)
        
        for vuln in analysis_results.get('vulnerabilities', []):
            pdf.set_font("Arial", "B", 12)
            # Ensure text fits within page width
            text = f"- {vuln['type']} ({vuln['severity']})"
            if pdf.get_string_width(text) > pdf.w - 40:
                text = text[:int(len(text) * 0.8)] + "..."
            pdf.cell(0, 10, text, ln=True)
            
            pdf.set_font("Arial", "", 12)
            # Add vulnerability details with proper wrapping
            details = [
                f"Line: {vuln.get('line', 'N/A')}",
                f"Description: {vuln.get('description', 'N/A')}",
                f"Explanation: {vuln.get('explanation', 'N/A')}",
                f"Fix: {vuln.get('fix', 'N/A')}",
                f"CWE: {vuln.get('cwe', 'N/A')}"
            ]
            
            for detail in details:
                for line in self._wrap_text(detail, pdf.w - 40):
                    pdf.cell(0, 10, line, ln=True)
            
            pdf.ln(5)
        
        # Code Analysis
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Code Analysis:", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Courier", "", 10)
        # Split code into lines and ensure they fit
        for line in code.split('\n'):
            if pdf.get_string_width(line) > pdf.w - 40:
                # Truncate long lines
                line = line[:int(len(line) * 0.8)] + "..."
            pdf.cell(0, 10, line, ln=True)
        
        # Save the report
        pdf.output(output_path)
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
    
    def generate_json_export(self, analysis_results: Dict[str, Any]) -> str:
        """Export analysis results in JSON format"""
        return json.dumps(analysis_results, indent=2)
    
    def _add_header(self, pdf: FPDF, title: str):
        """Add a header to the PDF with company info and timestamp"""
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, self.company_name, ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated: {self.timestamp}", ln=True)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, title, ln=True)
        pdf.ln(5)
    
    def _wrap_text(self, text: str, max_width: int) -> List[str]:
        """Wrap text to fit within the specified width"""
        words = text.split()
        lines = []
        current_line = []
        
        for word in words:
            # Simple ASCII character check
            word = ''.join(c if ord(c) < 128 else '-' for c in word)
            if len(current_line) + len(word) + 1 <= max_width:
                current_line.append(word)
            else:
                lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return lines
    
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
