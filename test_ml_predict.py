
from waf.ml_model import ml_detector
payload = ""
print(f"ML Prediction for empty payload: {ml_detector.predict(payload)}")
payload = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
print(f"ML Prediction for standard UA: {ml_detector.predict(payload)}")
