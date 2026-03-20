import joblib
import os
import math
import string
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

class MLDetector:
    def __init__(self, model_path='models/waf_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.threshold = -0.05 # Default sensitivity (negative is more aggressive)
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"Loaded ML model from {self.model_path}")
            except:
                self.model = None
        else:
            print(f"ML model not found at {self.model_path}")

    def set_sensitivity(self, level):
        """ level: 'low', 'medium', 'high' """
        if level == 'low':
            self.threshold = -0.15 # Less aggressive
        elif level == 'medium':
            self.threshold = -0.05
        elif level == 'high':
            self.threshold = 0.05 # More aggressive
            
    def calculate_entropy(self, s):
        if not s: return 0
        from collections import Counter
        l = len(s)
        counts = Counter(s)
        entropy = 0
        log2 = math.log(2.0)
        for count in counts.values():
            p = count / l
            entropy -= p * math.log(p) / log2
        return entropy

    def extract_features(self, payload):
        payload_str = str(payload or "")
        length = len(payload_str)
        special_chars = set("'\"<>;--/*%=")
        special_char_count = sum(1 for char in payload_str if char in special_chars)
        entropy = self.calculate_entropy(payload_str)
        keywords = ["SELECT", "UNION", "INSERT", "DROP", "script", "alert", "onerror", "eval", "javascript"]
        keyword_count = sum(1 for kw in keywords if kw.lower() in payload_str.lower())
        return [length, special_char_count, entropy, keyword_count]

    def predict(self, payload):
        if self.model is None:
            return 1 # Normal if no model
        
        features = [self.extract_features(payload)]
        # Use decision_function for more granular control
        score = self.model.decision_function(features)[0]
        
        # Isolation Forest decision_function returns negative for anomalies
        # We use a threshold to control sensitivity
        if score < self.threshold:
            return -1 # Malicious
        return 1 # Normal

    def train_new_model(self, extra_data=None):
        """
        Generates synthetic data (and optionally incorporates real feedback) 
        to retrain the Isolation Forest model.
        """
        print("Starting model retraining...")
        # 1. Generate core synthetic data
        normal_data = []
        for _ in range(4500):
            length = np.random.randint(5, 50)
            payload = ''.join(np.random.choice(list(string.ascii_letters + string.digits), length))
            normal_data.append(self.extract_features(payload))
            
        malicious_payloads = [
            "' OR 1=1 --", "<script>alert(1)</script>", "UNION SELECT NULL, username, password",
            "'; DROP TABLE users; --", "<img src=x onerror=alert(1)>", "admin'--", "javascript:alert(1)"
        ]
        malicious_data = []
        for _ in range(500):
            payload = np.random.choice(malicious_payloads)
            malicious_data.append(self.extract_features(payload))
            
        # 2. Incorporate extra_data (e.g. from false positive reports) if provided
        if extra_data:
            # extra_data should be a list of feature vectors
            normal_data.extend(extra_data)

        df = pd.DataFrame(normal_data + malicious_data, columns=['length', 'special_char_count', 'entropy', 'keyword_count'])
        
        # 3. Fit new model
        clf = IsolationForest(contamination=0.1, random_state=42)
        clf.fit(df)
        
        # 4. Save model
        if not os.path.exists('models'): os.makedirs('models')
        joblib.dump(clf, self.model_path)
        self.model = clf
        print("Model retraining completed and saved.")
        return True

# Singleton
ml_detector = MLDetector()
