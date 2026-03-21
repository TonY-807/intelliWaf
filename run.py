from app import app

if __name__ == "__main__":
    # Ensure database is initialized before running
    # This project uses app.py for everything but run.py is the standard entry point
    app.run(debug=True, port=5000)
