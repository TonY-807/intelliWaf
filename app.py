from flask import Flask, request, jsonify, render_template, abort, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import secrets
import requests

# Import WAF Engine
from waf.filter import waf_filter

app = Flask(__name__)
# Use environment variables for production security
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'instance', 'logs.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Models
class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45), index=True)
    payload = db.Column(db.Text)
    detection_result = db.Column(db.String(20), index=True)
    ml_anomaly = db.Column(db.Boolean)
    is_blocked = db.Column(db.Boolean, index=True)
    attack_type = db.Column(db.String(20), index=True)
    is_false_positive = db.Column(db.Boolean, default=False)

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Intercept every request
@app.before_request
def intercept_request():
    # Don't intercept dashboard related static/API routes to avoid recursive blocking
    # Also exclude the home page so you can actually see the test center!
    internal_apis = [
        '/api/stats', '/api/logs', '/api/toggle-ml', '/api/set-sensitivity', 
        '/api/train-model', '/api/mark-false-positive', '/api/stats/trends', 
        '/api/threat-intel', '/api/clear-logs'
    ]
    if request.path.startswith('/static') or request.path.startswith('/admin') or \
       request.path in internal_apis:
        return
    # This ensures that / and /login are scanned and logged as normal traffic

    # Process through WAF
    analysis = waf_filter.process_http_request(request)
    
    # Extract payload (for logging)
    payload = ""
    if request.args:
        payload += f"GET: {json.dumps(dict(request.args))} "
    if request.is_json:
        payload += f"JSON: {json.dumps(request.json)} "
    elif request.form:
        payload += f"FORM: {json.dumps(dict(request.form))} "
        
    # Log request
    log_entry = RequestLog(
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow(),
        payload=payload[:500], # Trucate long payloads
        detection_result=analysis["attack_type"],
        ml_anomaly=analysis["ml_anomaly"],
        is_blocked=analysis["is_malicious"],
        attack_type=analysis["attack_type"]
    )
    db.session.add(log_entry)
    db.session.commit()

    # Block malicious
    if analysis["is_malicious"]:
        abort(403, description=f"Malicious {analysis['attack_type']} attack detected and blocked by IntelliWAF.")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AdminUser.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@limiter.exempt
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# API Endpoints for Dashboard
@app.route('/api/stats')
@limiter.exempt
def get_stats():
    total_requests = RequestLog.query.count()
    blocked_requests = RequestLog.query.filter_by(is_blocked=True).count()
    sqli_count = RequestLog.query.filter_by(attack_type='SQLi').count()
    xss_count = RequestLog.query.filter_by(attack_type='XSS').count()
    anomaly_count = RequestLog.query.filter_by(attack_type='Anomaly').count()
    
    return jsonify({
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "sqli_count": sqli_count,
        "xss_count": xss_count,
        "anomaly_count": anomaly_count
    })

@app.route('/api/logs')
@limiter.exempt
def get_logs():
    limit = request.args.get('limit', 10, type=int)
    blocked_only = request.args.get('blocked_only', 'false').lower() == 'true'
    
    query = RequestLog.query
    if blocked_only:
        query = query.filter_by(is_blocked=True)
        
    logs = query.order_by(RequestLog.id.desc()).limit(limit).all()
    
    log_list = [{
        "id": log.id,
        "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "ip_address": log.ip_address,
        "payload": log.payload,
        "detection_result": log.detection_result,
        "is_blocked": log.is_blocked,
        "attack_type": log.attack_type,
        "is_false_positive": log.is_false_positive
    } for log in logs]
    
    return jsonify(log_list)

@app.route('/api/toggle-ml', methods=['POST'])
def toggle_ml():
    data = request.json
    enabled = data.get('enabled', True)
    waf_filter.ml_enabled = enabled
    return jsonify({"status": "success", "ml_enabled": enabled})

@app.route('/api/set-sensitivity', methods=['POST'])
def set_sensitivity():
    data = request.json
    level = data.get('level', 'medium')
    from waf.ml_model import ml_detector
    ml_detector.set_sensitivity(level)
    return jsonify({"status": "success", "level": level})

@app.route('/api/train-model', methods=['POST'])
def train_model():
    # Only allow admin
    if not session.get('logged_in'): return abort(401)
    
    from waf.ml_model import ml_detector
    # Find all false positives to use as normal data during retraining
    fp_logs = RequestLog.query.filter_by(is_false_positive=True).all()
    extra_data = [ml_detector.extract_features(log.payload) for log in fp_logs]
    
    success = ml_detector.train_new_model(extra_data=extra_data)
    return jsonify({"status": "success" if success else "error"})

@app.route('/api/mark-false-positive', methods=['POST'])
def mark_false_positive():
    data = request.json
    log_id = data.get('id')
    log = RequestLog.query.get(log_id)
    if log:
        log.is_false_positive = True
        # If it was blocked, we might want to unblock it in the system 
        # (Though it's already in the past)
        db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/stats/trends')
def get_trends():
    # Simple mock data for trends (since we might not have enough history)
    # real impl would GROUP BY date
    from sqlalchemy import func
    recent_logs = RequestLog.query.order_by(RequestLog.id.desc()).limit(100).all()
    # Mock some data for the line graph
    import random
    timestamps = [(datetime.utcnow().timestamp() - i*60)*1000 for i in range(10)][::-1]
    traffic = [random.randint(5, 20) for _ in range(10)]
    attacks = [random.randint(0, 5) for _ in range(10)]
    
    return jsonify({
        "timestamps": timestamps,
        "traffic": traffic,
        "attacks": attacks
    })

@app.route('/api/threat-intel')
def get_threat_intel():
    from sqlalchemy import func
    # Top IPs
    top_ips = db.session.query(RequestLog.ip_address, func.count(RequestLog.ip_address))\
        .filter_by(is_blocked=True)\
        .group_by(RequestLog.ip_address)\
        .order_by(func.count(RequestLog.ip_address).desc())\
        .limit(5).all()
    
    # Try to get real Geo-IP for the blocked IPs (simple mock/API mix)
    geo_attacks = []
    for ip, count in top_ips:
        try:
            # Use a free API for real-time intel
            # Note: 127.0.0.1 will always be local, so we mock those
            if ip in ['127.0.0.1', 'localhost']:
                geo_attacks.append({"lat": 40.7128, "lng": -74.0060, "name": f"Local Dev ({ip})", "count": count})
            else:
                resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                if resp['status'] == 'success':
                    geo_attacks.append({"lat": resp['lat'], "lng": resp['lon'], "name": f"{resp['city']}, {resp['country']}", "count": count})
        except:
            continue

    return jsonify({
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "geo_attacks": geo_attacks
    })

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        RequestLog.query.delete()
        db.session.commit()
        return jsonify({"status": "success", "message": "All logs cleared."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Sample vulnerable endpoint for testing
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q')
    return jsonify({"message": f"Results for: {query}"})

if __name__ == '__main__':
    with app.app_context():
        print(f"Current Working Directory: {os.getcwd()}")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.create_all()
        print("Database tables created successfully.")
        # Create a default admin user
        if not AdminUser.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash('password123')
            db.session.add(AdminUser(username='admin', password=hashed_pw))
            db.session.commit()
            print("Default admin user created.")
    app.run(debug=True, port=5000)
