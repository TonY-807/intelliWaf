import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import math
import string

def calculate_entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_features(payload):
    if payload is None:
        payload = ""
    
    length = len(str(payload))
    special_chars = set("'\"<>;--/*%=")
    special_char_count = sum(1 for char in str(payload) if char in special_chars)
    entropy = calculate_entropy(str(payload))
    
    keywords = ["SELECT", "UNION", "INSERT", "DROP", "script", "alert", "onerror", "eval", "javascript"]
    keyword_count = sum(1 for kw in keywords if kw.lower() in str(payload).lower())
    
    return [length, special_char_count, entropy, keyword_count]

def generate_synthetic_data(n_samples=5000):
    # Normal data: Random strings, short lengths, low entropy
    normal_data = []
    for _ in range(int(n_samples * 0.9)):
        length = np.random.randint(5, 50)
        payload = ''.join(np.random.choice(list(string.ascii_letters + string.digits), length))
        normal_data.append(extract_features(payload))
    
    # Malicious data: SQLi, XSS strings, longer, more special chars
    malicious_payloads = [
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "UNION SELECT NULL, username, password FROM users",
        "'; DROP TABLE users; --",
        "<img src=x onerror=alert('XSS')>",
        "SELECT * FROM accounts WHERE id = '10' OR '1'='1'",
        "admin'--",
        "javascript:alert(1)"
    ]
    
    malicious_data = []
    for _ in range(int(n_samples * 0.1)):
        payload = np.random.choice(malicious_payloads)
        malicious_data.append(extract_features(payload))
    
    df = pd.DataFrame(normal_data + malicious_data, columns=['length', 'special_char_count', 'entropy', 'keyword_count'])
    return df

def train_model():
    print("Generating synthetic dataset...")
    df = generate_synthetic_data()
    
    print("Training Isolation Forest model...")
    # Isolation Forest is great for outlier detection (malicious traffic are outliers)
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(df)
    
    if not os.path.exists('models'):
        os.makedirs('models')
        
    joblib.dump(clf, 'models/waf_model.pkl')
    print("Model saved to models/waf_model.pkl")

if __name__ == "__main__":
    train_model()
