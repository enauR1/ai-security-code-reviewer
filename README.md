# 🔒 AI Security Code Reviewer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io)
[![GitHub issues](https://img.shields.io/github/issues/enauR1/ai-security-code-reviewer)](https://github.com/enauR1/ai-security-code-reviewer/issues)
[![GitHub stars](https://img.shields.io/github/stars/enauR1/ai-security-code-reviewer)](https://github.com/enauR1/ai-security-code-reviewer/stargazers)

An intelligent, AI-powered code security analysis tool that helps developers identify and fix potential security vulnerabilities in their code. Powered by GPT-4 and Streamlit, this tool provides real-time security analysis with detailed reports and recommendations.

## 📋 Table of Contents
- [Features](#features)
- [Demo](#demo)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)
- [Acknowledgments](#acknowledgments)

## ✨ Features
- 🤖 AI-powered security vulnerability detection
- 🔍 Support for multiple programming languages (Python, JavaScript, Java, C++, C#)
- 📊 Interactive vulnerability visualization and statistics
- 📝 Detailed security reports (Executive and Technical)
- 🎨 Dark/Light theme support
- 🔎 Advanced search and filtering capabilities
- 📈 Severity-based vulnerability categorization
- 🔄 Real-time code analysis
- 📋 Code snippet highlighting and analysis
- 💡 Actionable fix recommendations

## 🖼️ Demo
![Dashboard Screenshot](docs/images/dashboard.png)
*Add your screenshots here*

## 🛠️ Technology Stack
- **Frontend**: Streamlit
- **Backend**: Python 3.9+
- **AI Engine**: OpenAI GPT-4
- **Data Visualization**: Plotly
- **PDF Generation**: ReportLab
- **Code Analysis**: Custom parsers and detectors
- **Testing**: Python unittest

## 📥 Installation

### Prerequisites
- Python 3.9 or higher
- OpenAI API key
- Git

### Step-by-Step Installation
1. Clone the repository:
```bash
git clone https://github.com/enauR1/ai-security-code-reviewer.git
cd ai-security-code-reviewer
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Create .env file
cp .env.example .env

# Edit .env with your OpenAI API key
OPENAI_API_KEY=your_api_key_here
```

## 🚀 Usage

### Starting the Application
```bash
streamlit run app.py
```

### Analyzing Code
1. Upload a code file or paste code directly
2. Select the programming language
3. Click "Analyze Code"
4. View the results and generated reports

### Code Example
```python
# Example: Analyzing a Python file
from analyzer.ai_engine import AISecurityAnalyzer

analyzer = AISecurityAnalyzer()
result = analyzer.analyze_code(code_content, language="python")
print(result['security_score'])
```

## ⚙️ Configuration

### Environment Variables
| Variable | Description | Required |
|----------|-------------|----------|
| OPENAI_API_KEY | Your OpenAI API key | Yes |
| STREAMLIT_THEME | Custom theme settings | No |
| MAX_FILE_SIZE | Maximum file size (default: 5MB) | No |
| MAX_CHAR_LENGTH | Maximum character length (default: 50K) | No |

### Customization Options
- Maximum file size: 5MB
- Maximum code length: 50,000 characters
- Supported file types: .py, .js, .java, .cpp, .cs, .txt

## 📁 Project Structure
```
ai-security-code-reviewer/
├── analyzer/
│   ├── ai_engine.py      # AI analysis core
│   ├── code_parser.py    # Code parsing utilities
│   └── report_gen.py     # Report generation
├── app.py                # Main Streamlit application
├── constants/
│   ├── secure_samples/   # Secure code examples
│   └── vulnerable_samples/ # Vulnerable code examples
├── utils/
│   └── language_detector.py # Language detection
├── docs/                 # Documentation
├── requirements.txt      # Project dependencies
└── README.md            # Project documentation
```

## 👥 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style
- Follow PEP 8 guidelines for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Write unit tests for new features

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author
Patrick
- GitHub: [@enauR1](https://github.com/enauR1)
- Email: [your.email@example.com]

## 🙏 Acknowledgments
- OpenAI for GPT-4 API
- Streamlit team for the amazing framework
- All contributors and users of this project
