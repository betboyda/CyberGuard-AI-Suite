import sys
import os

# --- scripts klasörünü path'e ekle (importlardan önce) ---
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
scripts_dir = os.path.join(base_dir, "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

import io
import json
import zipfile
import hashlib
import csv
from datetime import datetime
import time
import random

import pandas as pd
import joblib
import docx
import PyPDF2
import requests

from flask import Flask, render_template, request, redirect, url_for, Response, jsonify
from dotenv import load_dotenv

from url_analyzer import analyze_url_virustotal
from network_analyzer import analyze_live_traffic
from code_analyzer import analyze_code_with_bandit
from photo_fake_detector import predict_photo_deepfake
from predict import predict_file # malware tahmin fonksiyonu burada

import numpy as np
import cv2
from tensorflow.keras.models import load_model

load_dotenv(os.path.join(base_dir, ".env"))
VT_API_KEY = os.getenv("VT_API_KEY")

app = Flask(__name__)

# Bellekte URL ve Malware geçmişi tut
url_analysis_history = []
malware_history = []

# Model yolları
face_model_path = os.path.join(base_dir, "model", "face_model.h5")
malware_model_path = os.path.join(base_dir, "model", "malware_detector.pkl")
feature_list_path = os.path.join(base_dir, "model", "feature_names.txt")

model = joblib.load(malware_model_path)
with open(feature_list_path, "r") as f:
    expected_features = [line.strip() for line in f]

face_model = load_model(face_model_path)

# Yardımcı fonksiyon
def query_virustotal(file_bytes):
    if not VT_API_KEY:
        return "API anahtarı bulunamadı."
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return f"{stats['malicious']}/{sum(stats.values())} antivirüs zararlı dedi"
        elif response.status_code == 404:
            return "VirusTotal'da kayıt bulunamadı."
        else:
            return f"VirusTotal Hatası: {response.status_code}"
    except Exception as e:
        return f"VirusTotal Hatası: {str(e)}"

def prepare_dataframe(file, ext):
    if ext == ".csv":
        return pd.read_csv(file)
    elif ext == ".json":
        content = json.load(file)
        return pd.DataFrame([content]) if isinstance(content, dict) else pd.DataFrame(content)
    elif ext == ".pdf":
        reader = PyPDF2.PdfReader(file)
        text = " ".join(page.extract_text() or "" for page in reader.pages)
        return pd.DataFrame([{"pdf_text_length": len(text)}])
    elif ext == ".docx":
        doc = docx.Document(file)
        text = " ".join(para.text for para in doc.paragraphs)
        return pd.DataFrame([{"docx_text_length": len(text)}])
    elif ext == ".zip":
        with zipfile.ZipFile(file) as zip_ref:
            count = len(zip_ref.infolist())
        return pd.DataFrame([{"zip_file_count": count}])
    else:
        return None

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/network")
def network_analysis():
    return render_template("network_analysis.html")

@app.route("/url", methods=["GET", "POST"])
def url_analysis():
    global url_analysis_history
    result = None
    url = None

    if request.method == "POST":
        url = request.form.get("url_input")
        if url:
            vt_response = analyze_url_virustotal(url)
            result = vt_response
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            url_analysis_history.insert(0, {
                "url": url,
                "result": vt_response,
                "timestamp": timestamp
            })
            url_analysis_history = url_analysis_history[:10]

    return render_template("url_analysis.html", result=result, url=url, history=url_analysis_history)

@app.route("/clear_url_history", methods=["POST"])
def clear_url_history():
    global url_analysis_history
    url_analysis_history.clear()
    return redirect(url_for("url_analysis"))

@app.route("/network_data")
def network_data():
    data = []
    current_time = int(time.time())
    for i in range(10):
        data.append({
            "time": current_time - (9 - i),
            "source_ip": f"192.168.1.{random.randint(2,254)}",
            "dest_ip": f"8.8.8.{random.randint(1,254)}",
            "status": random.choice(["Güvenli", "Şüpheli", "Anomali"])
        })
    return jsonify({"results": data})

@app.route("/photo")
def photo_page():
    return render_template("upload_photo.html")

@app.route("/predict_photo", methods=["POST"])
def predict_photo():
    import tempfile

    photo_file = request.files.get("photo_file")
    if not photo_file:
        return render_template("upload_photo.html", result="Fotoğraf seçilmedi.")

    file_bytes = photo_file.read()
    nparr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        return render_template("upload_photo.html", result="Fotoğraf okunamadı.")

    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)

        if len(faces) == 0:
            return render_template("upload_photo.html", result="Fotoğrafta yüz bulunamadı.")

        (x, y, w, h) = faces[0]
        face_img = img[y:y + h, x:x + w]
        face_img = cv2.resize(face_img, (64, 64))

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            temp_path = tmp.name
            cv2.imwrite(temp_path, face_img)

        label = predict_photo_deepfake(temp_path, face_model_path)
        os.remove(temp_path)

        return render_template("upload_photo.html", result=f"Yüz analizi sonucu: {label}")

    except Exception as e:
        return render_template("upload_photo.html", result=f"Hata: {str(e)}")

@app.route("/code")
def code_page():
    return render_template("code_analysis.html")

@app.route("/analyze_code", methods=["POST"])
def analyze_code():
    code_file = request.files["code_file"]
    code_bytes = code_file.read()
    analysis_result = analyze_code_with_bandit(code_bytes)
    return render_template("code_analysis.html", analysis=analysis_result)

@app.route("/malware")
def malware_page():
    return render_template("malware_analysis.html", history=malware_history)

@app.route("/predict_malware", methods=["POST"])
def predict_malware():
    global malware_history
    file = request.files.get("malware_file")

    if not file:
        return render_template("malware_analysis.html", result="Dosya seçilmedi.", history=malware_history)

    try:
        prediction = predict_file(file)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        malware_history.insert(0, {
            "filename": file.filename,
            "result": prediction,
            "timestamp": timestamp
        })
        malware_history = malware_history[:10]

        return render_template("malware_analysis.html", result=f"Tahmin: {prediction}", history=malware_history)
    except Exception as e:
        return render_template("malware_analysis.html", result=f"Hata: {str(e)}", history=malware_history)

@app.route("/clear_malware_history", methods=["POST"])
def clear_malware_history():
    global malware_history
    malware_history.clear()
    return redirect(url_for("malware_page"))

if __name__ == "__main__":
    app.run(debug=True)
