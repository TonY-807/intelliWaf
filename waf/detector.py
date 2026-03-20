import re

class PatternDetector:
    def __init__(self):
        # SQL Injection Patterns
        self.sqli_patterns = [
            r"(\d+\s+(OR|AND)\s+\d+\s*=\s*\d+)",
            r"('.*OR.*'.*=.*')",
            r"(UNION\s+SELECT)",
            r"(DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+.*SET)",
            r"(--|#|\/\*)",
            r"(SELECT\s+.*\s+FROM\s+.*)",
            r"(' OR '1'='1')",
            # Removed overly broad semicolon pattern that flags standard User-Agents
            r"(;\s*(DROP|DELETE|UPDATE|SELECT|INSERT|UNION|OR|AND))",
        ]
        
        # XSS Patterns
        self.xss_patterns = [
            r"(<script.*?>.*?<\/script>)",
            r"((onerror|onclick|onload|onmouseover|onfocus)\s*=)",
            r"(<img\s+.*?src=.*?onerror=.*?>)",
            r"(<iframe.*?>.*?<\/iframe>)",
            r"(javascript:.*)",
            r"(alert\(.*?\))",
            r"(eval\(.*?\))",
        ]

    def check_sqli(self, payload):
        if not payload:
            return False
        
        payload = str(payload).upper()
        for pattern in self.sqli_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def check_xss(self, payload):
        if not payload:
            return False
            
        payload = str(payload).lower()
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def check_malicious(self, payload):
        """Returns (is_malicious, attack_type)"""
        if self.check_sqli(payload):
            return True, "SQLi"
        if self.check_xss(payload):
            return True, "XSS"
        return False, None

# Singleton
detector = PatternDetector()
