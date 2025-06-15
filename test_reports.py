import json
from analyzer.ai_engine import AISecurityAnalyzer
from analyzer.report_gen import ReportGenerator

def test_report_generation():
    print("🧪 Testing Report Generation...")
    print("=" * 50)
    
    # Sample vulnerable Python code for testing
    test_code = '''
import sqlite3
import os

def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL injection
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    result = cursor.fetchone()
    
    # Vulnerable command injection
    os.system(f"echo 'Processing user {user_id}'")
    
    return result

def unsafe_pickle_load(data):
    import pickle
    return pickle.loads(data)  # Dangerous deserialization
    '''
    
    # Initialize analyzers
    ai_analyzer = AISecurityAnalyzer()
    report_generator = ReportGenerator(
        company_name="AI Security Code Reviewer",
        company_logo=None  # You can add a logo path here if you have one
    )
    
    print("🔍 Step 1: Analyzing code...")
    # Analyze the test code
    analysis_results = ai_analyzer.analyze_code(test_code, "python")
    
    if 'error' in analysis_results:
        print(f"❌ Analysis failed: {analysis_results['error']}")
        return
    
    print(f"✅ Analysis complete! Found {len(analysis_results.get('vulnerabilities', []))} vulnerabilities")
    print(f"📊 Security Score: {analysis_results.get('security_score', 0)}/100")
    
    print("\n📄 Step 2: Generating reports...")
    
    # Test 1: Executive PDF
    try:
        executive_path = report_generator.generate_executive_pdf(
            analysis_results, 
            "executive_report.pdf"
        )
        print(f"✅ Executive PDF created: {executive_path}")
    except Exception as e:
        print(f"❌ Executive PDF failed: {e}")
    
    # Test 2: Technical PDF
    try:
        technical_path = report_generator.generate_technical_pdf(
            analysis_results, 
            test_code,
            "technical_report.pdf"
        )
        print(f"✅ Technical PDF created: {technical_path}")
    except Exception as e:
        print(f"❌ Technical PDF failed: {e}")
    
    # Test 3: HTML Report
    try:
        html_content = report_generator.generate_html_report(analysis_results, test_code)
        with open("interactive_report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        print("✅ HTML report created: interactive_report.html")
    except Exception as e:
        print(f"❌ HTML report failed: {e}")
    
    # Test 4: JSON Export
    try:
        json_content = report_generator.generate_json_export(analysis_results)
        with open("analysis_export.json", "w", encoding="utf-8") as f:
            f.write(json_content)
        print("✅ JSON export created: analysis_export.json")
    except Exception as e:
        print(f"❌ JSON export failed: {e}")
    
    print("\n🎉 Report generation testing complete!")
    print("\nGenerated files:")
    print("📋 executive_report.pdf - Executive summary")
    print("📋 technical_report.pdf - Detailed technical analysis")
    print("🌐 interactive_report.html - Interactive web report")
    print("📄 analysis_export.json - Raw data export")

if __name__ == "__main__":
    test_report_generation() 