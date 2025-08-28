# Detectify: High-Speed Fraudulent App Detection System 🛡️🔍

**Detectify** is a high-performance, multi-layered security system designed to analyze Android application packages (`.apk`) and classify them as Safe, Fraudulent, or Unknown. It specializes in protecting users from malicious clones and tampered versions of major Indian banking and UPI applications using a rapid, self-learning analysis engine.

---

## 🚀 Key Features

-   **High-Speed Analysis**: Utilizes the **Androguard** library for rapid, in-memory static analysis, avoiding slow external tool calls.
-   **Multi-Layered Security Model**: Employs a robust, five-layer security model for deep inspection of APKs.
-   **Smart Self-Learning**: Automatically learns and saves the correct cryptographic signatures of trusted apps on their first scan, ensuring Layer 2 accuracy over time.
-   **Comprehensive Databases**: Leverages curated lists of trusted applications and known fraudulent hashes for accurate classification.
-   **User-Friendly Web Interface**: A clean, responsive UI for easy APK uploads and clear, card-based reporting of analysis results.
-   **RESTful API**: A Flask-based backend that handles the analysis logic and serves the results.

---

## ⚙️ How It Works: The Security Layers

Detectify analyzes an APK through a sequence of critical and non-critical security checks. An app is only classified as **Safe** if it passes all critical layers.

### Layer 1: Package Name Match (Critical)
-   **Purpose**: To verify the app's fundamental identity.
-   **Check**: Compares the APK's package name (e.g., `com.sbi.yono`) against the official package names in the `trusted_apps.json` database.

### Layer 2: Developer Signature Check (Warning)
-   **Purpose**: To check the integrity of the app's certificate.
-   **Check**: Compares the APK's certificate SHA256 hash against the hash stored in the database. A mismatch issues a warning, as this can change with legitimate app updates. The system will self-learn the correct hash on the first scan.

### Layer 3: VirusTotal API Check (Critical - Simulated)
-   **Purpose**: To leverage a third-party service for known malware detection.
-   **Check**: Simulates an API call to VirusTotal using the app's file hash.

### Layer 4: Known Fraud Hash Match (Critical)
-   **Purpose**: A rapid check against a blacklist of known malicious app fingerprints.
-   **Check**: Compares the APK's file hash against the `known_fraud.json` database.

### Layer 5: Heuristics Check (Warning)
-   **Purpose**: To identify suspicious permission anomalies.
-   **Check**: Flags any dangerous permissions that are not part of the app's official list.

---

## 🛠️ Tech Stack

-   **Backend**: Python, Flask, **Androguard**
-   **Frontend**: HTML, CSS, JavaScript

---

## 📂 Project Structure


/Final Prototype/
├── app.py                  # Flask backend server
├── check.py                # Core analysis logic with Androguard
├── trusted_apps.json       # Database of trusted apps
├── known_fraud.json        # Database of known fraudulent APK hashes
├── requirements.txt        # Python package requirements
├── templates/
│   └── index.html          # Main HTML file for the UI
└── static/
├── style.css           # CSS for styling the UI
└── script.js           # JavaScript for the frontend


---

## 🏁 Getting Started

### Prerequisites

-   Python 3.x
-   `pip` and `venv`

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/detectify.git](https://github.com/your-username/detectify.git)
    cd detectify
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```
    *(This will install Flask, Flask-CORS, and Androguard)*

4.  **Run the backend server:**
    ```bash
    python app.py
    ```
    The server will start on `http://127.0.0.1:5000`.

5.  **Open the application:**
    Open your web browser and navigate to `http://127.0.0.1:5000`. You can now upload an APK file for analysis.
