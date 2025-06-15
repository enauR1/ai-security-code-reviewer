# Open AI Integration

import openai
import os
from dotenv import load_dotenv
import json
from typing import Dict, List

load_dotenv()

class AISecurityAnalyzer:
    def __init__(self):
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found. Check your .env file.")
        self.client = openai.OpenAI(api_key=api_key)
        
        # Language-specific analysis templates
        self.language_templates = {
            "python": {
                "focus_areas": [
                    "SQL Injection (CWE-89)",
                    "Command Injection (CWE-78)",
                    "Path Traversal (CWE-22)",
                    "Pickle Deserialization (CWE-502)",
                    "Insecure Deserialization (CWE-502)",
                    "Hardcoded Credentials (CWE-798)",
                    "Insecure Crypto (CWE-326)",
                    "OS Command Injection (CWE-78)"
                ],
                "example_vulnerabilities": [
                    {
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "line_number": 5,
                        "description": "User input directly concatenated into SQL query",
                        "explanation": "This allows attackers to inject malicious SQL commands",
                        "fix": "Use parameterized queries with placeholders",
                        "cwe_id": "CWE-89"
                    },
                    {
                        "type": "Command Injection",
                        "severity": "Critical",
                        "line_number": 8,
                        "description": "User input used in os.system() call",
                        "explanation": "This allows attackers to execute arbitrary commands",
                        "fix": "Use subprocess.run() with shell=False and proper argument lists",
                        "cwe_id": "CWE-78"
                    }
                ],
                "severity_guidelines": {
                    "Critical": ["SQL Injection", "Command Injection", "Pickle Deserialization"],
                    "High": ["Path Traversal", "Insecure Deserialization", "Hardcoded Credentials"],
                    "Medium": ["Insecure Crypto", "OS Command Injection"],
                    "Low": ["Information Disclosure", "Weak Password Requirements"]
                }
            },
            "javascript": {
                "focus_areas": [
                    "Cross-Site Scripting (CWE-79)",
                    "Prototype Pollution (CWE-1321)",
                    "Eval Injection (CWE-95)",
                    "DOM-based XSS (CWE-79)",
                    "Insecure Deserialization (CWE-502)",
                    "Insecure Direct Object References (CWE-639)",
                    "Client-side Storage (CWE-922)",
                    "Insecure Communication (CWE-319)"
                ],
                "example_vulnerabilities": [
                    {
                        "type": "Cross-Site Scripting",
                        "severity": "Critical",
                        "line_number": 3,
                        "description": "User input directly inserted into innerHTML",
                        "explanation": "This allows attackers to inject malicious JavaScript",
                        "fix": "Use textContent or proper HTML sanitization",
                        "cwe_id": "CWE-79"
                    },
                    {
                        "type": "Prototype Pollution",
                        "severity": "High",
                        "line_number": 7,
                        "description": "User input used in Object.assign() without validation",
                        "explanation": "This allows attackers to modify object prototypes",
                        "fix": "Use Object.freeze() or validate input before assignment",
                        "cwe_id": "CWE-1321"
                    }
                ],
                "severity_guidelines": {
                    "Critical": ["XSS", "Prototype Pollution", "Eval Injection"],
                    "High": ["DOM-based XSS", "Insecure Deserialization"],
                    "Medium": ["Insecure Direct Object References", "Client-side Storage"],
                    "Low": ["Information Disclosure", "Weak Password Requirements"]
                }
            },
            "java": {
                "focus_areas": [
                    "SQL Injection (CWE-89)",
                    "XML Injection (CWE-91)",
                    "Insecure Deserialization (CWE-502)",
                    "Path Traversal (CWE-22)",
                    "Command Injection (CWE-78)",
                    "Insecure Crypto (CWE-326)",
                    "Weak Password Requirements (CWE-521)",
                    "Information Disclosure (CWE-200)"
                ],
                "example_vulnerabilities": [
                    {
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "line_number": 5,
                        "description": "User input concatenated into SQL query string",
                        "explanation": "This allows attackers to inject malicious SQL commands",
                        "fix": "Use PreparedStatement with parameterized queries",
                        "cwe_id": "CWE-89"
                    },
                    {
                        "type": "XML Injection",
                        "severity": "High",
                        "line_number": 8,
                        "description": "User input used in XML construction without sanitization",
                        "explanation": "This allows attackers to inject malicious XML content",
                        "fix": "Use XML escaping or proper XML parsers",
                        "cwe_id": "CWE-91"
                    }
                ],
                "severity_guidelines": {
                    "Critical": ["SQL Injection", "XML Injection", "Command Injection"],
                    "High": ["Insecure Deserialization", "Path Traversal"],
                    "Medium": ["Insecure Crypto", "Weak Password Requirements"],
                    "Low": ["Information Disclosure", "Debug Information"]
                }
            },
            "cpp": {
                "focus_areas": [
                    "Buffer Overflow (CWE-120)",
                    "Memory Leak (CWE-401)",
                    "Format String Bug (CWE-134)",
                    "Integer Overflow (CWE-190)",
                    "Use After Free (CWE-416)",
                    "Double Free (CWE-415)",
                    "Race Condition (CWE-362)",
                    "Null Pointer Dereference (CWE-476)"
                ],
                "example_vulnerabilities": [
                    {
                        "type": "Buffer Overflow",
                        "severity": "Critical",
                        "line_number": 5,
                        "description": "Fixed-size buffer with unchecked input",
                        "explanation": "This allows attackers to overwrite adjacent memory",
                        "fix": "Use bounds checking or safer alternatives like std::string",
                        "cwe_id": "CWE-120"
                    },
                    {
                        "type": "Memory Leak",
                        "severity": "High",
                        "line_number": 8,
                        "description": "Allocated memory not freed in error path",
                        "explanation": "This leads to memory exhaustion over time",
                        "fix": "Use RAII or smart pointers for automatic cleanup",
                        "cwe_id": "CWE-401"
                    }
                ],
                "severity_guidelines": {
                    "Critical": ["Buffer Overflow", "Use After Free", "Double Free"],
                    "High": ["Memory Leak", "Format String Bug"],
                    "Medium": ["Integer Overflow", "Race Condition"],
                    "Low": ["Null Pointer Dereference", "Debug Information"]
                }
            },
            "csharp": {
                "focus_areas": [
                    "SQL Injection (CWE-89)",
                    "XPath Injection (CWE-643)",
                    "Insecure Deserialization (CWE-502)",
                    "Weak Crypto (CWE-326)",
                    "Path Traversal (CWE-22)",
                    "Command Injection (CWE-78)",
                    "Information Disclosure (CWE-200)",
                    "Weak Password Requirements (CWE-521)"
                ],
                "example_vulnerabilities": [
                    {
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "line_number": 5,
                        "description": "User input concatenated into SQL query string",
                        "explanation": "This allows attackers to inject malicious SQL commands",
                        "fix": "Use parameterized queries with SqlCommand",
                        "cwe_id": "CWE-89"
                    },
                    {
                        "type": "XPath Injection",
                        "severity": "High",
                        "line_number": 8,
                        "description": "User input used in XPath query without sanitization",
                        "explanation": "This allows attackers to inject malicious XPath expressions",
                        "fix": "Use parameterized XPath queries",
                        "cwe_id": "CWE-643"
                    }
                ],
                "severity_guidelines": {
                    "Critical": ["SQL Injection", "XPath Injection", "Command Injection"],
                    "High": ["Insecure Deserialization", "Weak Crypto"],
                    "Medium": ["Path Traversal", "Weak Password Requirements"],
                    "Low": ["Information Disclosure", "Debug Information"]
                }
            }
        }
    
    def analyze_code(self, code: str, language: str = "python") -> Dict:
        """Analyze code for security vulnerabilities using OpenAI"""
        if not code.strip():
            return {"error": "No code provided for analysis"}
            
        prompt = self._create_analysis_prompt(code, language)
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity expert specializing in code vulnerability analysis. Return structured JSON responses only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2000
            )
            
            result = self._parse_response(response.choices[0].message.content)
            return result
            
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _create_analysis_prompt(self, code: str, language: str) -> str:
        """Create a language-specific analysis prompt"""
        if language not in self.language_templates:
            language = "python"  # Default to Python if language not supported
            
        template = self.language_templates[language]
        
        # Build focus areas string
        focus_areas = "\n".join([f"- {area}" for area in template["focus_areas"]])
        
        # Build example vulnerabilities string
        example_vulns = json.dumps(template["example_vulnerabilities"], indent=2)
        
        # Build severity guidelines string
        severity_guidelines = "\n".join([
            f"{severity}:\n" + "\n".join([f"- {vuln}" for vuln in vulns])
            for severity, vulns in template["severity_guidelines"].items()
        ])
        
        return f"""
Analyze this {language} code for security vulnerabilities and return ONLY valid JSON:

```{language}
{code}
```

Focus on these specific areas for {language}:
{focus_areas}

Example vulnerability format:
{example_vulns}

Severity guidelines for {language}:
{severity_guidelines}

Return exactly this JSON structure:
{{
    "vulnerabilities": [
        {{
            "type": "Vulnerability Type",
            "severity": "Critical|High|Medium|Low",
            "line_number": 5,
            "description": "Detailed description of the vulnerability",
            "explanation": "Technical explanation of why it's vulnerable",
            "fix": "Specific fix recommendation",
            "cwe_id": "CWE-XXX"
        }}
    ],
    "security_score": 75,
    "overall_assessment": "Code contains X vulnerabilities with Y critical issues"
}}

Ensure all vulnerabilities follow the severity guidelines and include appropriate CWE IDs.
"""
    
    def _parse_response(self, response_text: str) -> Dict:
        """Parse AI response into structured format"""
        try:
            # Find JSON in response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            
            if start == -1 or end == 0:
                raise ValueError("No JSON found in response")
                
            json_str = response_text[start:end]
            parsed = json.loads(json_str)
            
            # Validate required fields
            if 'vulnerabilities' not in parsed:
                parsed['vulnerabilities'] = []
            if 'security_score' not in parsed:
                parsed['security_score'] = 50
            if 'overall_assessment' not in parsed:
                parsed['overall_assessment'] = "Analysis completed"
                
            return parsed
            
        except Exception as e:
            return {
                "vulnerabilities": [],
                "security_score": 0,
                "overall_assessment": f"Failed to parse AI response: {str(e)}",
                "raw_response": response_text
            }
