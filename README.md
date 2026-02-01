# CyberGuard-AI-Suite
AI-powered multi-layer cybersecurity analysis platform


CyberGuard AI Suite is a multi-layer, AI-powered cybersecurity analysis platform developed during an internship in the cybersecurity department.  
The system combines multiple security-focused modules under a single web-based interface to analyze files, images, code, URLs, and network data.

##  Project Purpose
The main goal of CyberGuard AI Suite is to automatically detect potential cyber threats by analyzing user-uploaded content using machine learning and deep learning techniques.  
The platform aims to support early threat detection against malware, DeepFake content, phishing attempts, insecure code, and suspicious network activities.

##  Technologies Used
- Python
- Flask
- TensorFlow / Keras
- Scikit-learn
- OpenCV
- SQLite
- VirusTotal API
- Bandit (Code Security Scanner)

##  System Modules

### 1- Malware Analysis Module
- Machine learning-based malware classification using application permission data.
- SHA-256 hash generation and VirusTotal API integration.
- Local prediction results and VirusTotal scan results are shown together.
- Analysis history is stored in SQLite and can be exported as CSV.

### 2- Photo DeepFake Detection Module
- CNN-based model trained on real and fake face images.
- Face detection using OpenCV.
- Images are resized to 64x64 and classified as **Real** or **Fake**.

### 3- Network Traffic Analysis Module
- Simulated or real-time network traffic monitoring.
- Detection of suspicious and anomalous traffic patterns.
- Results are visualized using tables and charts in the web interface.

### 4- Code Security Analysis Module
- Python (.py) files are scanned using the Bandit security tool.
- Detection of insecure functions such as `eval`, `exec`, and `subprocess`.
- Security findings are categorized as Safe, Warning, or Critical.

### 5- URL Analysis Module
- User-submitted URLs are analyzed via VirusTotal.
- The number of malicious, suspicious, and clean detections is reported.

##  Web Interface
- Developed using Flask and Jinja2.
- User-friendly, modular, and responsive design.
- All analysis results are displayed as structured and color-coded result boxes.

##  Installation & Usage
```bash
pip install -r requirements.txt
python app.py
