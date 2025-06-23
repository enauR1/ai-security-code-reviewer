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
        
        # Use a single comprehensive prompt; language-specific templates removed for simplicity
    
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
        """Create a simple, comprehensive analysis prompt."""
        return f"""
Analyze this {language} code for ALL security vulnerabilities. Look for OWASP Top 10 issues, CWE categories, and any security problems.

Return ONLY valid JSON in the following format:

{{
  "vulnerabilities": [
    {{
      "type": "Vulnerability type (e.g., SQL Injection)",
      "severity": "Critical|High|Medium|Low",
      "line_number": 0,
      "description": "Short description of the issue",
      "explanation": "Detailed technical explanation of why it's vulnerable",
      "fix": "Clear guidance on how to remediate",
      "cwe_id": "CWE-###"
    }}
  ],
  "security_score": 0,
  "overall_assessment": "High-level summary of the code security posture"
}}

Only output the JSON. Do NOT wrap it in markdown fences or any extra text.

Here is the code to analyze:

```{language}
{code}
```
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
