# app.py

import os
import tempfile
import shutil
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from check import analyze_apk, load_database_from_file

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)

# Enable CORS only for API routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- Load Databases at Startup ---
print("Loading security databases...")
TRUSTED_DB_FILE = 'trusted_apps.json'
KNOWN_FRAUD_DB_FILE = 'known_fraud.json'

try:
    trusted_apps_db = load_database_from_file(TRUSTED_DB_FILE)
    known_fraud_db = load_database_from_file(KNOWN_FRAUD_DB_FILE)
    print("Databases loaded successfully.")
except Exception as e:
    print(f"Warning: Could not load databases - {e}")
    trusted_apps_db = {}
    known_fraud_db = {}

# --- Route to serve the main HTML page ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about_page.html')

# --- Serve static files ---
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# --- API Backend Route for Analysis ---
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    if not trusted_apps_db and not known_fraud_db:
        return jsonify({"error": "Server not configured; databases missing."}), 500

    if 'apk_file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files['apk_file']
    if file.filename == '' or not file.filename.endswith('.apk'):
        return jsonify({"error": "No APK file selected or invalid file type."}), 400

    temp_dir = tempfile.mkdtemp()
    apk_path = os.path.join(temp_dir, secure_filename(file.filename))

    try:
        file.save(apk_path)
        analysis_result = analyze_apk(apk_path, trusted_apps_db, known_fraud_db)
        return jsonify(analysis_result)
    except Exception as e:
        print(f"Error during analysis: {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

# --- Error handlers ---
@app.errorhandler(404)
def not_found_error(error):
    # Return HTML for page routes, JSON for API
    if request.path.startswith('/api/'):
        return jsonify({"error": "Endpoint not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Internal server error"}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    print("Starting APK Security Analyzer server...")
    print("Server will be available at: http://127.0.0.1:5000")
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, host='127.0.0.1', port=5000)