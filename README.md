# 🛡️ IntelliWAF - Intelligent Web Application Firewall

IntelliWAF is a modern, production-ready Web Application Firewall (WAF) that leverages **Machine Learning** and **Pattern Matching** to monitor, filter, and block malicious HTTP traffic in real-time.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Shield](https://img.shields.io/badge/Security-Advanced-green)

---

## 🚀 Key Features

- **Real-time Traffic Filtering**: Intercepts GET, POST, and Header data to identify threats.
- **Dual Detection Engine**:
    - **Heuristic (Regex)**: Instantly detect SQL Injection (SQLi) and Cross-Site Scripting (XSS).
    - **ML-based (Isolation Forest)**: Detects zero-day anomalies and suspicious patterns that bypass traditional rules.
- **Modern SOC Dashboard**: A premium, dark-themed admin interface with live logs, attack distribution charts, and system controls.
- **Smart Blocking**: Automatically drops malicious requests with `403 Forbidden` responses.
- **Rate Limiting**: Protects against basic DDoS and brute-force attempts.
- **Logging System**: Persistent SQLite database to track every request and security event.

---

## 🛠️ Tech Stack

- **Backend**: Python (Flask)
- **Database**: SQLite (SQLAlchemy ORM)
- **Machine Learning**: Scikit-learn (Isolation Forest), Pandas, Joblib
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (ES6), Chart.js
- **Security**: JWT-based Authentication, Flask-Limiter

---

## 📦 Project Structure

```text
IntelliWAF/
│── app.py                 # Main Flask Backend & Request Interceptor
│── waf/
│   ├── filter.py          # Core Filtering Engine (Rules + ML)
│   ├── detector.py        # Regex-based Attack Detector 
│   └── ml_model.py        # ML Prediction Wrapper
│── templates/             # UI Templates (Dashboard, Login, Landing)
│── static/                # Modern UI Assets (CSS, JS)
│── dataset/               # ML Dataset Generation & Training Tools
│── models/                # Pre-trained ML Models (.pkl)
│── logs/                  # Application Logs
│── requirements.txt       # Dependencies
└── README.md              # Project Documentation
```

---

## 🔧 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/IntelliWAF.git
   cd IntelliWAF
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the ML Model**
   Generate the synthetic dataset and train the Isolation Forest anomaly detector:
   ```bash
   python dataset/generate_and_train.py
   ```

4. **Run the Firewall**
   ```bash
   python app.py
   ```

5. **Access the Dashboard**
   - **Main UI**: `http://localhost:5000`
   - **Admin Dashboard**: `http://localhost:5000/login`
   - **Default Credentials**: 
     - Username: `admin`
     - Password: `password123`

---

## 🛡️ Example Attack Testing

You can use the built-in testing center on the home page or try these manual payloads:

| Type | Payload Example | Result |
|------|-----------------|--------|
| **SQLi** | `admin' OR '1'='1` | **403 Blocked** |
| **XSS** | `<script>alert('IntelliWAF')</script>` | **403 Blocked** |
| **Anomaly** | Extremely long random strings with high entropy | **ML Detected** |

---

## 🧪 Machine Learning Details

IntelliWAF uses an **Isolation Forest** algorithm. It treats malicious requests as outliers. The model is trained on:
- **Payload Length**: Malicious strings are often unusually long.
- **Special Character Density**: Frequency of characters like `' " < > ; --`.
- **Character Entropy**: Detects obfuscated or encoded malicious payloads.
- **Keyword Frequency**: Checks for sensitive SQL/JS keywords.

---

## 👨‍💻 Author
**Antigravity AI (on behalf of USER)**

---

*Disclaimer: This project is for educational and internship purposes. Always use a layered security approach for production systems.*
