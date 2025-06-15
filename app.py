import streamlit as st
import json
import plotly.express as px
import pandas as pd
from analyzer.ai_engine import AISecurityAnalyzer
from analyzer.report_gen import ReportGenerator
from dotenv import load_dotenv

# Page config
st.set_page_config(
    page_title="AI Security Code Reviewer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(90deg, #1e3c72, #2a5298);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #2a5298;
    }
    .vulnerability-critical {
        border-left: 4px solid #e74c3c;
        background: #fdf2f2;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .vulnerability-high {
        border-left: 4px solid #f39c12;
        background: #fef9f3;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .vulnerability-medium {
        border-left: 4px solid #f1c40f;
        background: #fefdf2;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .vulnerability-low {
        border-left: 4px solid #27ae60;
        background: #f2fdf2;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🤖 AI Security Code Reviewer</h1>
        <p>Intelligent Vulnerability Detection with AI-Powered Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'code_input' not in st.session_state:
        st.session_state.code_input = ""
    
    # Sidebar
    with st.sidebar:
        st.header("🔧 Configuration")
        
        language = st.selectbox(
            "Programming Language",
            ["python", "javascript", "java", "cpp", "csharp"],
            help="Select the programming language of your code"
        )
        
        st.header("📊 Analysis Statistics")
        if st.session_state.analysis_results:
            display_sidebar_stats(st.session_state.analysis_results)
        else:
            st.info("Run an analysis to see statistics")
        
        st.header("ℹ️ About")
        st.info("""
        This tool uses GPT-4 to analyze your code for security vulnerabilities.
        
        **Supported Languages:**
        - Python
        - JavaScript
        - Java
        - C++
        - C#
        """)
    
    # Main content
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("📝 Code Input")
        
        # File upload option
        uploaded_file = st.file_uploader(
            "Upload a code file",
            type=['py', 'js', 'java', 'cpp', 'cs', 'txt'],
            help="Upload a code file for analysis"
        )
        
        # Code input area
        if uploaded_file:
            st.session_state.code_input = str(uploaded_file.read(), "utf-8")
            st.text_area("Uploaded Code:", value=st.session_state.code_input, height=300, disabled=True)
        else:
            st.session_state.code_input = st.text_area(
                "Paste your code here:",
                height=400,
                placeholder=get_sample_code(language),
                help="Paste or type your code here for security analysis"
            )
        
        # Analysis button
        analyze_button = st.button(
            "🔍 Analyze Code", 
            type="primary",
            disabled=not st.session_state.code_input.strip(),
            help="Click to start AI security analysis"
        )
    
    with col2:
        st.header("🚨 Analysis Results")
        
        if analyze_button and st.session_state.code_input.strip():
            with st.spinner("🤖 AI is analyzing your code for security vulnerabilities..."):
                try:
                    analyzer = AISecurityAnalyzer()
                    result = analyzer.analyze_code(st.session_state.code_input.strip(), language)
                    st.session_state.analysis_results = result
                    
                    if 'error' in result:
                        st.error(f"❌ Analysis Error: {result['error']}")
                    else:
                        display_analysis_results(result)
                        
                except Exception as e:
                    st.error(f"❌ Failed to initialize analyzer: {str(e)}")
                    st.info("💡 Make sure your OpenAI API key is set in the .env file")
        
        elif st.session_state.analysis_results:
            display_analysis_results(st.session_state.analysis_results)
        
        else:
            st.info("👆 Enter code above and click 'Analyze Code' to get started")

def display_analysis_results(result):
    """Display formatted analysis results"""
    
    if 'error' in result:
        st.error(f"❌ {result['error']}")
        return
    
    # Security Score
    score = result.get('security_score', 0)
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if score >= 80:
            st.success(f"🏆 Security Score: {score}/100")
        elif score >= 60:
            st.warning(f"⚠️ Security Score: {score}/100")
        else:
            st.error(f"🚨 Security Score: {score}/100")
    
    with col2:
        vulns = result.get('vulnerabilities', [])
        st.metric("Issues Found", len(vulns))
    
    with col3:
        critical_count = len([v for v in vulns if v.get('severity') == 'Critical'])
        if critical_count > 0:
            st.error(f"🚨 Critical: {critical_count}")
        else:
            st.success("✅ No Critical Issues")
    
    # Overall Assessment
    if 'overall_assessment' in result:
        st.info(f"📋 **Assessment:** {result['overall_assessment']}")
    
    # Vulnerabilities
    vulnerabilities = result.get('vulnerabilities', [])
    
    if vulnerabilities:
        st.subheader("🔍 Detected Vulnerabilities")
        
        for i, vuln in enumerate(vulnerabilities):
            display_vulnerability(vuln, i)
        
        # Vulnerability chart
        if len(vulnerabilities) > 0:
            create_vulnerability_chart(vulnerabilities)
    else:
        st.success("✅ No security vulnerabilities detected!")
        st.balloons()
    
    # Raw data (for debugging)
    with st.expander("🔧 Raw Analysis Data"):
        st.json(result)
    
    # Add report generation section
    st.header("📄 Generate Reports")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📋 Executive PDF"):
            report_gen = ReportGenerator("AI Security Code Reviewer")
            pdf_path = report_gen.generate_executive_pdf(result, "executive_report.pdf")
            
            with open(pdf_path, "rb") as pdf_file:
                st.download_button(
                    "⬬ Download Executive PDF",
                    pdf_file.read(),
                    "security_executive_report.pdf",
                    "application/pdf"
                )
    
    with col2:
        if st.button("🔧 Technical PDF"):
            report_gen = ReportGenerator("AI Security Code Reviewer")
            pdf_path = report_gen.generate_technical_pdf(result, st.session_state.code_input, "technical_report.pdf")
            
            with open(pdf_path, "rb") as pdf_file:
                st.download_button(
                    "⬬ Download Technical PDF",
                    pdf_file.read(),
                    "security_technical_report.pdf",
                    "application/pdf"
                )
    
    with col3:
        if st.button("🌐 HTML Report"):
            report_gen = ReportGenerator("AI Security Code Reviewer")
            html_content = report_gen.generate_html_report(result, st.session_state.code_input)
            
            st.download_button(
                "⬬ Download HTML Report",
                html_content,
                "security_report.html",
                "text/html"
            )

def display_vulnerability(vuln, index):
    """Display individual vulnerability with styling"""
    severity = vuln.get('severity', 'Unknown').lower()
    vuln_type = vuln.get('type', 'Unknown Vulnerability')
    line_num = vuln.get('line_number', '?')
    
    # Choose styling based on severity
    if severity == 'critical':
        st.markdown('<div class="vulnerability-critical">', unsafe_allow_html=True)
        st.error(f"🚨 **{vuln_type}** (Line {line_num})")
    elif severity == 'high':
        st.markdown('<div class="vulnerability-high">', unsafe_allow_html=True)
        st.warning(f"⚠️ **{vuln_type}** (Line {line_num})")
    elif severity == 'medium':
        st.markdown('<div class="vulnerability-medium">', unsafe_allow_html=True)
        st.info(f"💡 **{vuln_type}** (Line {line_num})")
    else:
        st.markdown('<div class="vulnerability-low">', unsafe_allow_html=True)
        st.success(f"✅ **{vuln_type}** (Line {line_num})")
    
    # Expandable details
    with st.expander(f"Details - {vuln_type}"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"**Description:** {vuln.get('description', 'No description available')}")
            st.write(f"**Severity:** {vuln.get('severity', 'Unknown')}")
            if 'cwe_id' in vuln:
                st.write(f"**CWE ID:** {vuln['cwe_id']}")
        
        with col2:
            st.write(f"**Explanation:** {vuln.get('explanation', 'No explanation available')}")
            st.write(f"**How to Fix:** {vuln.get('fix', 'No fix guidance available')}")
    
    st.markdown('</div>', unsafe_allow_html=True)

def display_sidebar_stats(result):
    """Display statistics in sidebar"""
    vulnerabilities = result.get('vulnerabilities', [])
    
    # Count by severity
    critical = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high = len([v for v in vulnerabilities if v.get('severity') == 'High'])
    medium = len([v for v in vulnerabilities if v.get('severity') == 'Medium'])
    low = len([v for v in vulnerabilities if v.get('severity') == 'Low'])
    
    # Display metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Critical", critical)
        st.metric("High", high)
    with col2:
        st.metric("Medium", medium)
        st.metric("Low", low)
    
    st.metric("Security Score", f"{result.get('security_score', 0)}/100")

def create_vulnerability_chart(vulnerabilities):
    """Create vulnerability distribution chart"""
    st.subheader("📊 Vulnerability Distribution")
    
    # Count by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    if severity_counts:
        # Create pie chart
        df = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
        
        color_map = {
            'Critical': '#e74c3c',
            'High': '#f39c12', 
            'Medium': '#f1c40f',
            'Low': '#27ae60'
        }
        
        fig = px.pie(df, values='Count', names='Severity', 
                    title="Vulnerabilities by Severity",
                    color='Severity',
                    color_discrete_map=color_map)
        
        st.plotly_chart(fig, use_container_width=True)

def get_sample_code(language):
    """Get sample vulnerable code for the selected language"""
    samples = {
        "python": '''# Example Python code with SQL injection vulnerability
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def authenticate(username, password):
    if username == "admin" and password == "admin123":
        return True
    return False''',
        
        "javascript": '''// Example JavaScript code with XSS vulnerability
function displayUserInput(userInput) {
    document.getElementById("output").innerHTML = userInput;
}

function login(username, password) {
    if (username === "admin" && password === "admin123") {
        return true;
    }
    return false;
}''',
        
        "java": '''// Example Java code with command injection
import java.io.*;

public class FileManager {
    public void deleteFile(String filename) {
        try {
            String command = "rm " + filename;
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}''',
        
        "cpp": '''// Example C++ code with buffer overflow
#include <cstring>
#include <iostream>

void processInput(char* input) {
    char buffer[100];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
    std::cout << buffer << std::endl;
}''',
        
        "csharp": '''// Example C# code with SQL injection
using System;
using System.Data.SqlClient;

public class UserService {
    public User GetUser(string userId) {
        string connectionString = "server=localhost;database=mydb;";
        string query = "SELECT * FROM Users WHERE Id = '" + userId + "'";
        
        using (SqlConnection conn = new SqlConnection(connectionString)) {
            SqlCommand cmd = new SqlCommand(query, conn);
            // Execute query...
        }
    }
}'''
    }
    
    return samples.get(language, "# Paste your code here...")

if __name__ == "__main__":
    main()
