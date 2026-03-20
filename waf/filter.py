from .detector import detector
from .ml_model import ml_detector
import json

class WAFFilter:
    def __init__(self, ml_enabled=True):
        self.ml_enabled = ml_enabled

    def analyze_request(self, request_data):
        """
        Analyzes a single request (GET/POST params, headers, body)
        Returns: {
            "is_malicious": bool,
            "attack_type": str (SQLi/XSS/Anomaly),
            "ml_anomaly": bool,
            "confidence": float
        }
        """
        is_malicious = False
        attack_type = "Normal"
        ml_anomaly = False
        
        # 1. Rule-based detection (high confidence detections)
        is_malicious, attack_type = detector.check_malicious(request_data)
        
        # 2. ML-based detection (if rule-based didn't catch it and ML is enabled)
        if not is_malicious and self.ml_enabled:
            # -1 = anomaly (malicious), 1 = normal
            prediction = ml_detector.predict(request_data)
            if prediction == -1:
                ml_anomaly = True
                is_malicious = True
                attack_type = "Anomaly"
        
        return {
            "is_malicious": is_malicious,
            "attack_type": attack_type,
            "ml_anomaly": ml_anomaly
        }

    def process_http_request(self, request):
        """
        Extracts parameters and payloads from a Flask request objects
        """
        # Combine parameters to check
        params_to_check = []
        
        # 1. URL Args (GET)
        for key, value in request.args.items():
            params_to_check.append(value)
            
        # 2. JSON/Form (POST)
        if request.is_json:
            try:
                params_to_check.append(json.dumps(request.json))
            except:
                pass
        elif request.form:
            for key, value in request.form.items():
                params_to_check.append(value)
        
        # 3. User-Agent and other headers (for header injection)
        headers_to_check = ['User-Agent', 'Referer']
        for header in headers_to_check:
            val = request.headers.get(header)
            if val:
                params_to_check.append(val)
                
        # Run check
        final_result = {"is_malicious": False, "attack_type": "Normal", "ml_anomaly": False}
        
        for payload in params_to_check:
            result = self.analyze_request(payload)
            if result["is_malicious"]:
                return result # Return the first malicious result
                
        return final_result

# Singleton
waf_filter = WAFFilter()
