import streamlit as st
import json
import plotly.express as px
import pandas as pd
from analyzer.ai_engine import AISecurityAnalyzer
from analyzer.report_gen import ReportGenerator
from dotenv import load_dotenv
from utils.language_detector import LanguageDetector

# Constants
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
MAX_CODE_LENGTH = 50000  # 50K characters

# Page config
st.set_page_config(
    page_title="AI Security Code Reviewer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

def apply_theme_css(is_dark_mode):
    """Apply theme-specific CSS"""
    if is_dark_mode:
        st.markdown("""
        <style>
        /* Force dark theme for Streamlit */
        .stApp {
            background-color: #0e1117 !important;
            color: #fafafa !important;
        }
        
        /* All text elements */
        .stApp * {
            color: #fafafa !important;
        }
        
        /* Headers and subheaders */
        .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
            color: #fafafa !important;
        }
        
        /* Main content area */
        .main .block-container {
            background-color: #0e1117 !important;
        }
        
        /* Header styling for dark mode */
        .main-header-dark {
            text-align: center;
            padding: 1rem 0;
            background: linear-gradient(90deg, #1a1a2e, #16213e);
            color: white !important;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        /* Dark vulnerability cards */
        .vuln-critical-dark {
            background: #2d1b1b !important;
            border-left: 4px solid #e74c3c;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
            color: #fafafa !important;
        }
        
        .vuln-high-dark {
            background: #2d2419 !important;
            border-left: 4px solid #f39c12;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
            color: #fafafa !important;
        }
        
        .vuln-medium-dark {
            background: #2d2b19 !important;
            border-left: 4px solid #f1c40f;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
            color: #fafafa !important;
        }
        
        .vuln-low-dark {
            background: #1b2d1b !important;
            border-left: 4px solid #27ae60;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
            color: #fafafa !important;
        }
        
        /* Comprehensive text styling for dark mode */
        .stMarkdown, .stMarkdown p, .stMarkdown div, .stMarkdown span {
            color: #fafafa !important;
        }
        
        /* Form elements */
        .stSelectbox label, .stTextInput label, .stTextArea label, .stFileUploader label {
            color: #fafafa !important;
        }
        
        .stSelectbox > div > div {
            background-color: #262730 !important;
            color: #fafafa !important;
        }
        
        .stTextArea textarea {
            background-color: #262730 !important;
            color: #fafafa !important;
            border: 1px solid #4a4a4a !important;
        }
        
        .stTextInput input {
            background-color: #262730 !important;
            color: #fafafa !important;
            border: 1px solid #4a4a4a !important;
        }
        
        /* Metrics */
        [data-testid="metric-container"] {
            background-color: #262730 !important;
            border: 1px solid #4a4a4a !important;
            border-radius: 5px !important;
            padding: 10px !important;
        }
        
        [data-testid="metric-container"] * {
            color: #fafafa !important;
        }
        
        /* Info, success, warning, error boxes */
        .stAlert {
            background-color: #262730 !important;
            color: #fafafa !important;
        }
        
        .stAlert * {
            color: #fafafa !important;
        }
        
        /* Expanders */
        .stExpander {
            background-color: #262730 !important;
            border: 1px solid #4a4a4a !important;
        }
        
        .stExpander * {
            color: #fafafa !important;
        }
        
        /* Buttons */
        .stButton > button {
            background-color: #4a90e2 !important;
            color: white !important;
            border: 1px solid #4a90e2 !important;
        }
        
        .stDownloadButton > button {
            background-color: #27ae60 !important;
            color: white !important;
            border: 1px solid #27ae60 !important;
        }
        
        /* Sidebar dark styling */
        section[data-testid="stSidebar"] {
            background-color: #1e1e1e !important;
        }
        
        section[data-testid="stSidebar"] * {
            color: #fafafa !important;
        }
        
        section[data-testid="stSidebar"] .stMarkdown {
            color: #fafafa !important;
        }
        
        section[data-testid="stSidebar"] [data-testid="metric-container"] {
            background-color: #2a2a2a !important;
            border: 1px solid #4a4a4a !important;
        }
        
        /* JSON viewer */
        .stJson {
            background-color: #262730 !important;
            color: #fafafa !important;
        }
        
        /* Spinner */
        .stSpinner {
            color: #fafafa !important;
        }
        
        /* File uploader - comprehensive fix */
        .stFileUploader {
            background-color: #262730 !important;
            border: 1px solid #4a4a4a !important;
            border-radius: 5px !important;
        }
        
        .stFileUploader * {
            color: #fafafa !important;
        }
        
        /* Target the drag-and-drop area specifically */
        .stFileUploader > div {
            background-color: #262730 !important;
            border: 2px dashed #4a4a4a !important;
            color: #fafafa !important;
        }
        
        .stFileUploader > div > div {
            background-color: #262730 !important;
            color: #fafafa !important;
        }
        
        /* File uploader text and labels */
        .stFileUploader label {
            color: #fafafa !important;
        }
        
        .stFileUploader small {
            color: #cccccc !important;
        }
        
        /* Drag area text */
        [data-testid="stFileUploader"] {
            background-color: #262730 !important;
        }
        
        [data-testid="stFileUploader"] * {
            color: #fafafa !important;
            background-color: transparent !important;
        }
        
        [data-testid="stFileUploader"] > div {
            background-color: #262730 !important;
            border: 2px dashed #4a4a4a !important;
        }
        
        /* Tables */
        .stDataFrame, .stTable {
            background-color: #262730 !important;
            color: #fafafa !important;
        }
        
        .stDataFrame * {
            color: #fafafa !important;
        }
        
        /* Code blocks */
        .stCode {
            background-color: #1a1a1a !important;
            color: #fafafa !important;
        }
        </style>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <style>
        /* Light theme (default) */
        .main-header-light {
            text-align: center;
            padding: 1rem 0;
            background: linear-gradient(90deg, #1e3c72, #2a5298);
            color: white;
            border-radius: 10px;
            margin-bottom: 2rem;
        }
        
        .vuln-critical-light {
            border-left: 4px solid #e74c3c;
            background: #fdf2f2;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
        }
        
        .vuln-high-light {
            border-left: 4px solid #f39c12;
            background: #fef9f3;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
        }
        
        .vuln-medium-light {
            border-left: 4px solid #f1c40f;
            background: #fefdf2;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
        }
        
        .vuln-low-light {
            border-left: 4px solid #27ae60;
            background: #f2fdf2;
            padding: 1rem;
            border-radius: 5px;
            margin: 0.5rem 0;
        }
        </style>
        """, unsafe_allow_html=True)

def main():
    # Initialize dark mode in session state
    if 'dark_mode' not in st.session_state:
        st.session_state.dark_mode = False
    
    # Apply theme CSS first
    apply_theme_css(st.session_state.dark_mode)
    
    # Initialize other session state
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'code_input' not in st.session_state:
        st.session_state.code_input = ""
    
    # Header with theme-aware styling
    header_class = "main-header-dark" if st.session_state.dark_mode else "main-header-light"
    st.markdown(f"""
    <div class="{header_class}">
        <h1>🤖 AI Security Code Reviewer</h1>
        <p>Intelligent Vulnerability Detection with AI-Powered Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar with theme toggle
    with st.sidebar:
        st.header("🎨 Theme Settings")
        
        # Simple toggle using columns for better layout
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("🌙 Dark" if not st.session_state.dark_mode else "☀️ Light", 
                        key="theme_toggle", use_container_width=True):
                st.session_state.dark_mode = not st.session_state.dark_mode
                st.rerun()
        
        with col2:
            # Status indicator
            status = "🌙 Dark Mode" if st.session_state.dark_mode else "☀️ Light Mode"
            st.write(f"**{status}**")
        
        st.divider()
        
        st.header("🔧 Configuration")
        
        # Initialize language detector if code is present
        default_language = "python"
        if st.session_state.code_input.strip():
            detector = LanguageDetector()
            detected_lang, confidence = detector.detect_language(st.session_state.code_input.strip())
            if detected_lang != 'unknown' and confidence > 60:
                default_language = detected_lang
        
        # Use session state to persist language selection
        if 'selected_language' not in st.session_state:
            st.session_state.selected_language = default_language
        
        language = st.selectbox(
            "Programming Language",
            ["python", "javascript", "java", "cpp", "csharp"],
            index=["python", "javascript", "java", "cpp", "csharp"].index(st.session_state.selected_language),
            help="Select the programming language of your code"
        )
        st.session_state.selected_language = language
        
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
        
        # File upload option with size validation
        uploaded_file = st.file_uploader(
            "Upload a code file (Max 5MB, 50K chars)",
            type=['py', 'js', 'java', 'cpp', 'cs', 'txt'],
            help="Upload a code file for analysis"
        )
        
        if uploaded_file:
            # Check file size before reading
            if uploaded_file.size > MAX_FILE_SIZE:
                st.error(f"❌ File too large! Maximum size is {MAX_FILE_SIZE/(1024*1024):.1f}MB. Your file: {uploaded_file.size/(1024*1024):.1f}MB")
                st.stop()
            
            try:
                # Read file content
                file_content = str(uploaded_file.read(), "utf-8")
                
                # Check character count
                if len(file_content) > MAX_CODE_LENGTH:
                    st.error(f"❌ File content too long! Maximum {MAX_CODE_LENGTH:,} characters. Your file: {len(file_content):,} characters")
                    st.info("💡 Try uploading a smaller code file or paste specific functions instead")
                    st.stop()
                
                # File is valid - proceed
                st.session_state.code_input = file_content
                st.success(f"✅ File uploaded successfully! ({len(file_content):,} characters)")
                st.text_area("Uploaded Code:", value=st.session_state.code_input, height=300, disabled=True)
                
            except UnicodeDecodeError:
                st.error("❌ Cannot read file. Please upload a valid text file with UTF-8 encoding")
                st.info("💡 Supported file types: .py, .js, .java, .cpp, .cs, .txt")
                st.stop()
            except Exception as e:
                st.error(f"❌ Error reading file: {str(e)}")
                st.stop()
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
        
        # Instruction message positioned below the input area
        if not st.session_state.code_input.strip():
            st.info("👆 Enter code above and click 'Analyze Code' to get started")
    
    with col2:
        st.header("🚨 Analysis Results")
        
        if analyze_button and st.session_state.code_input.strip():
            with st.spinner("🤖 AI is analyzing your code for security vulnerabilities..."):
                try:
                    # Detect language mismatch before analysis
                    detector = LanguageDetector()
                    detected_lang, confidence = detector.detect_language(st.session_state.code_input.strip(), uploaded_file.name if 'uploaded_file' in locals() and uploaded_file else None)
                    
                    # Always show detected language and confidence
                    st.info(f"🔍 Detected Language: **{detected_lang.capitalize()}** (Confidence: **{confidence:.0f}%**)")
                    
                    # Show warning only on mismatch with high confidence
                    if detected_lang != 'unknown' and detected_lang != language and confidence > 60:
                        st.warning(
                            f"⚠️ **Language Mismatch**: Selected {language.capitalize()}, but detected {detected_lang.capitalize()} "
                            f"with {confidence:.0f}% confidence. Analysis may be less accurate.")
                        
                        # Add suggestion for user
                        if st.button(f"Switch to {detected_lang.capitalize()}"):
                            st.session_state.selected_language = detected_lang
                            st.rerun()

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
            st.write("")  # Empty space when no results

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
        # Initialize reset state if not exists
        if 'reset_filters' not in st.session_state:
            st.session_state.reset_filters = False
        
        # Search and filter section
        st.subheader("🔍 Filter Results")
        col1, col2, col3 = st.columns([2, 1, 1])
        
        # Handle reset logic
        if st.session_state.reset_filters:
            search_default = ""
            severity_default = "All"
            st.session_state.reset_filters = False
        else:
            search_default = st.session_state.get('vuln_search', "")
            severity_default = st.session_state.get('severity_filter', "All")
        
        with col1:
            search = st.text_input(
                "Search vulnerabilities",
                value=search_default,
                placeholder="Search in descriptions and types...",
                key="vuln_search"
            ).lower()
        
        with col2:
            severity = st.selectbox(
                "Filter by Severity",
                ["All", "Critical", "High", "Medium", "Low"],
                index=["All", "Critical", "High", "Medium", "Low"].index(severity_default),
                key="severity_filter"
            )
        
        with col3:
            if st.button("Clear Filters", use_container_width=True):
                st.session_state.reset_filters = True
                st.rerun()
        
        # Apply filters
        filtered_vulns = vulnerabilities
        if search:
            filtered_vulns = [
                v for v in filtered_vulns
                if search in v.get('type', '').lower() or 
                   search in v.get('description', '').lower()
            ]
        
        if severity != "All":
            filtered_vulns = [
                v for v in filtered_vulns
                if v.get('severity') == severity
            ]
        
        # Show filtered results count
        total_count = len(vulnerabilities)
        filtered_count = len(filtered_vulns)
        if search or severity != "All":
            st.write(f"Showing {filtered_count} of {total_count} vulnerabilities")
        
        st.subheader("🔍 Detected Vulnerabilities")
        
        if not filtered_vulns:
            st.warning("No vulnerabilities match the current filters")
        else:
            for i, vuln in enumerate(filtered_vulns):
                display_vulnerability(vuln, i)
            
            # Vulnerability chart
            if len(filtered_vulns) > 0:
                create_vulnerability_chart(filtered_vulns)
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
    """Display individual vulnerability with theme-aware styling"""
    severity = vuln.get('severity', 'Unknown').lower()
    vuln_type = vuln.get('type', 'Unknown Vulnerability')
    line_num = vuln.get('line_number', '?')
    
    # Choose styling based on severity and theme
    theme_suffix = "-dark" if st.session_state.dark_mode else "-light"
    
    if severity == 'critical':
        st.markdown(f'<div class="vuln-critical{theme_suffix}">', unsafe_allow_html=True)
        st.error(f"🚨 **{vuln_type}** (Line {line_num})")
    elif severity == 'high':
        st.markdown(f'<div class="vuln-high{theme_suffix}">', unsafe_allow_html=True)
        st.warning(f"⚠️ **{vuln_type}** (Line {line_num})")
    elif severity == 'medium':
        st.markdown(f'<div class="vuln-medium{theme_suffix}">', unsafe_allow_html=True)
        st.info(f"💡 **{vuln_type}** (Line {line_num})")
    else:
        st.markdown(f'<div class="vuln-low{theme_suffix}">', unsafe_allow_html=True)
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
    """Create vulnerability distribution chart with theme support"""
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
        
        # Apply dark theme to chart if in dark mode
        if st.session_state.get('dark_mode', False):
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(14,17,23,1)',  # Dark background
                font_color='#fafafa',
                title_font_color='#fafafa'
            )
        else:
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(255,255,255,1)',  # Light background
                font_color='#000000'
            )
        
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