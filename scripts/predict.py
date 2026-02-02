import pandas as pd
import joblib
import os
import json

# Proje ana dizini
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
model_path = os.path.join(base_dir, "model", "malware_detector.pkl")

# === Modeli Yükle ===
model = joblib.load(model_path)

def predict_file(csv_path=None, json_path=None):
    """
    csv_path, json_path: opsiyonel, veri dosyası yolu.
    Eğer verilmez veya dosya bulunamazsa manuel örnek veri kullanılır.
    
    Dönüş: Tahmin sonuçlarının listesi ["ZARARLI", "ZARARSIZ", ...]
    """

    sample_data = {
        'android.permission.INTERNET': 1,
        'android.permission.ACCESS_NETWORK_STATE': 1,
        'android.permission.WRITE_EXTERNAL_STORAGE': 0,
        'android.permission.READ_PHONE_STATE': 1,
        'android.permission.ACCESS_WIFI_STATE': 0,
        'android.permission.WAKE_LOCK': 0,
        'android.permission.ACCESS_COARSE_LOCATION': 1,
        'android.permission.RECEIVE_BOOT_COMPLETED': 0,
        'android.permission.ACCESS_FINE_LOCATION': 1,
        'android.permission.VIBRATE': 1,
    }

    df = None

    # Dosya yoluna göre veri oku
    if csv_path and os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        print(f"[OK] CSV dosyası yüklendi: {csv_path}")

    elif json_path and os.path.exists(json_path):
        with open(json_path, "r") as f:
            json_data = json.load(f)
        if isinstance(json_data, dict):
            df = pd.DataFrame([json_data])
        else:
            df = pd.DataFrame(json_data)
        print(f"[OK] JSON dosyası yüklendi: {json_path}")

    # Dosya yoksa manuel örnek veri kullan
    if df is None:
        df = pd.DataFrame([sample_data])
        print("[INFO] Dosya bulunamadı. Manuel veri kullanılıyor.")

    # Modelin beklediği özelliklere göre sütunları ayarla
    df = df.reindex(columns=model.feature_names_in_, fill_value=0)

    # Tahmin yap
    predictions = model.predict(df)

    # Sonuçları listeye çevir
    results = []
    for pred in predictions:
        sonuc = "ZARARLI" if pred == 1 else "ZARARSIZ"
        results.append(sonuc)

    return results

# Eğer doğrudan çalıştırılırsa örnek test
if __name__ == "__main__":
    csv_file = os.path.join(base_dir, "data", "sample_data.csv")
    json_file = os.path.join(base_dir, "data", "sample_data.json")
    tahminler = predict_file(csv_path=csv_file, json_path=json_file)
    for i, t in enumerate(tahminler, 1):
        print(f"{i}. Uygulama: {t} olabilir.")
