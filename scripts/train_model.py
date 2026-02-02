import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# === Veri seti dosya yolu ===
DATA_PATH = os.path.join("data", "Android_Malware.csv")

# === Veriyi oku ===
df = pd.read_csv(DATA_PATH)

# === Özellikler ve etiketleri ayır ===
X = df.drop(columns=["Result"])
y = df["Result"]

# === Yeni dosya türlerinden gelen sütunları tanımla ===
additional_features = [
    "pdf_text_length", "pdf_has_author", "pdf_has_title", "pdf_has_producer",
    "docx_text_length", "docx_num_paragraphs", "docx_num_images",
    "zip_file_count"
]

# === Eksik olanları 0 ile ekle ===
for col in additional_features:
    if col not in X.columns:
        X[col] = 0  # Model bu sütunları tanımalı

# === Veriyi eğitim ve test olarak böl ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# === Modeli oluştur ve eğit ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Tahmin yap ===
y_pred = model.predict(X_test)

# === Sonuçları yazdır ===
print(" Doğruluk Oranı:", accuracy_score(y_test, y_pred))
print("\n Sınıflandırma Raporu:\n", classification_report(y_test, y_pred))
print("\n Karışıklık Matrisi:\n", confusion_matrix(y_test, y_pred))

# === Modeli kaydet ===
MODEL_PATH = os.path.join("model", "malware_detector.pkl")
joblib.dump(model, MODEL_PATH)
print(f"\n Model kaydedildi: {MODEL_PATH}")

# === Özellik isimlerini kaydet ===
FEATURES_PATH = os.path.join("model", "feature_names.txt")
with open(FEATURES_PATH, "w") as f:
    for col in X.columns:
        f.write(col + "\n")

print(f" Özellik isimleri kaydedildi: {FEATURES_PATH}")
