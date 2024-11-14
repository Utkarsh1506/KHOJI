from flask import Flask, request, jsonify, render_template
import os
import hashlib
import math
import joblib

app = Flask(__name__)

# Load the ML model
try:
    model = joblib.load("ml_model/ransomware_detector.pkl")
except FileNotFoundError:
    raise Exception("ML model file not found. Ensure 'ransomware_detector.pkl' exists in the 'ml_model' directory.")

def calculate_entropy(file_path):
    """
    Calculate the Shannon entropy of a file to detect encryption.
    """
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        probabilities = [data.count(byte) / len(data) for byte in set(data)]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        return entropy

@app.route("/")
def home():
    """
    Render the homepage with file upload and scan options.
    """
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_file():
    """
    Handle file upload and scan for ransomware.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]

    # Ensure the 'uploads' directory exists
    os.makedirs("uploads", exist_ok=True)

    try:
        file_path = os.path.join("uploads", uploaded_file.filename)
        uploaded_file.save(file_path)  # Save uploaded file

        # Calculate entropy
        entropy = calculate_entropy(file_path)

        # Create features for ML model
        features = [entropy]
        prediction = model.predict([features])[0]

        # Clean up the uploaded file
        os.remove(file_path)

        # Return JSON response based on prediction
        if prediction == 1:
            return jsonify({
                "status": "Ransomware Detected",
                "entropy": entropy,
                "logs": [
                    "High entropy detected in the file.",
                    "The file exhibits ransomware-like behavior."
                ],
                "mitigations": [
                    "Isolate the file and affected system immediately.",
                    "Restore files from a secure backup.",
                    "Run a complete anti-virus scan."
                ]
            }), 200
        else:
            return jsonify({
                "status": "Safe",
                "entropy": entropy
            }), 200

    except Exception as e:
        print(f"Error occurred: {e}")  # Log the error for debugging
        return jsonify({"error": "Internal server error", "message": str(e)}), 500

if __name__ == "__main__":
    # Start the Flask server
    app.run(debug=True, port=5000)
