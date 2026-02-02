import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# === Veri dosyasının yolu ===
DATA_PATH = os.path.join("data", "Android_Malware.csv")

# === CSV dosyasını oku ===
df = pd.read_csv(DATA_PATH)

# === Veri seti boyutu ve sütunlar ===
print("Veri Seti Boyutu:", df.shape)
print("Sütunlar:", df.columns.tolist())

# === İlk 5 satırı göster ===
print("\nİlk 5 Satır:\n", df.head())

# === Eksik veri kontrolü ===
print("\nEksik Veri Sayısı:\n", df.isnull().sum())

# === 'Result' sütunu varsa sınıf dağılımını göster ===
if 'Result' in df.columns:
    print("\nSınıf Dağılımı (0: Benign, 1: Malware):")
    print(df['Result'].value_counts())
else:
    print("\n'ıResult' sütunu bulunamadı!")

# === Sınıf dağılımını görselleştir ===
if 'Result' in df.columns:
    sns.countplot(x='Result', data=df)
    plt.title("Zararlı ve Zararsız Uygulama Dağılımı")
    plt.xlabel("Sınıf (0=Benign, 1=Malware)")
    plt.ylabel("Adet")
    plt.tight_layout()
    plt.show()

# === En çok kullanılan izinleri say ===
permission_totals = df.drop(columns=['Result']).sum().sort_values(ascending=False).head(10)
print("\nEn Çok Kullanılan 10 İzin:\n", permission_totals)

# === En çok kullanılan izinlerin grafik gösterimi ===
plt.figure(figsize=(10, 5))
sns.barplot(x=permission_totals.values, y=permission_totals.index)
plt.title("En Çok Kullanılan İzinler")
plt.xlabel("Kullanım Sayısı")
plt.tight_layout()
plt.show()
