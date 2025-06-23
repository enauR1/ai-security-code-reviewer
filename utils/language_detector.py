import re
import os
from typing import Tuple

class LanguageDetector:
    """Simple file-extension and regex-pattern based language detector."""

    _LANG_PATTERNS = {
        "python": {
            "ext": [".py"],
            "regex": [r"\bdef\s+\w+\s*\(", r"\bclass\s+\w+", r"if\s+__name__\s*=="]
        },
        "javascript": {
            "ext": [".js", ".jsx", ".ts", ".tsx"],
            "regex": [r"\bfunction\s+\w+\s*\(", r"(var|let|const)\s+\w+", r"console\.log"]
        },
        "java": {
            "ext": [".java"],
            "regex": [r"public\s+class\s+\w+", r"public\s+static\s+void\s+main"]
        },
        "cpp": {
            "ext": [".cpp", ".cc", ".hpp", ".h"],
            "regex": [r"#include\s*<", r"using\s+namespace\s+std", r"cout\s*<<"]
        },
        "csharp": {
            "ext": [".cs"],
            "regex": [r"using\s+System", r"namespace\s+\w+", r"Console\.WriteLine"]
        }
    }

    def detect_language(self, code: str, filename: str | None = None) -> Tuple[str, float]:
        """Return (language, confidence 0-100)."""
        if not code.strip():
            return ("unknown", 0.0)

        # Check extension first
        if filename:
            ext = os.path.splitext(filename)[1].lower()
            for lang, info in self._LANG_PATTERNS.items():
                if ext in info["ext"]:
                    # simple high confidence from extension
                    return (lang, 90.0)

        # Pattern matching
        best_lang = "unknown"
        best_score = 0
        for lang, info in self._LANG_PATTERNS.items():
            score = 0
            for pattern in info["regex"]:
                if re.search(pattern, code, re.MULTILINE):
                    score += 1
            # Convert to confidence percentage
            confidence = score / len(info["regex"]) * 100
            if confidence > best_score:
                best_score = confidence
                best_lang = lang
        return (best_lang, best_score) 