import os
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def query_virustotal(file_bytes):
    if not VT_API_KEY:
        return "API anahtarı bulunamadı."

    # SHA-256 hashini al
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() # HTTP hataları için istisna fırlat

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        total_engines = sum(stats.values())
        return f"{stats['malicious']} / {total_engines} antivirüs motoru zararlı olarak işaretledi."

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return "Bu dosya VirusTotal veritabanında kayıtlı değil."
        else:
            return f"VirusTotal Hatası: {e.response.status_code} - {e.response.text}"
    except requests.exceptions.ConnectionError:
        return "Bağlantı hatası oluştu. İnternet bağlantınızı kontrol edin."
    except requests.exceptions.Timeout:
        return "VirusTotal isteği zaman aşımına uğradı."
    except requests.exceptions.RequestException as e:
        return f"Beklenmeyen bir hata oluştu: {e}"