from app import app, db, RequestLog
with app.app_context():
    count = RequestLog.query.count()
    blocked = RequestLog.query.filter_by(is_blocked=True).count()
    print(f"Total Logs: {count}")
    print(f"Blocked Logs: {blocked}")
