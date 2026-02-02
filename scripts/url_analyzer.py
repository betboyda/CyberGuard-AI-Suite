import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def analyze_url_virustotal(url: str) -> str:
    if not VT_API_KEY:
        return "VT API anahtarı bulunamadı."

    headers = {"x-apikey": VT_API_KEY}

    try:
        # URL'yi base64 ile VT'ye özel şekilde encode et (padding karakterlerini kaldır)
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # VT'den analiz sonucunu çek
        result_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(result_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            return f"VirusTotal sonucu: {malicious} zararlı, {suspicious} şüpheli, {harmless} temiz / Toplam: {total}"
        elif response.status_code == 404:
            return "Bu URL için VirusTotal'da kayıt bulunamadı."
        else:
            return f"VT Sonuç Hatası: {response.status_code}"

    except Exception as e:
        return f"VirusTotal Hatası: {str(e)}"



