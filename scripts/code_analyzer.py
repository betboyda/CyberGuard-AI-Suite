import subprocess
import tempfile
import os

def analyze_code_with_bandit(code_bytes):
    """
    Gelen Python kodunu Bandit ile analiz eder ve raporu string olarak döner.
    """
    try:
        # Geçici dosya oluştur (kod burada yazılacak)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp_file:
            tmp_file.write(code_bytes)
            tmp_path = tmp_file.name

        # Bandit komutunu subprocess ile çalıştır
        # -f txt: çıktı formatı text
        # -q: sadece uyarılar
        # --exit-zero: hata olsa da çıkış kodu 0 olur
        result = subprocess.run(
            ["bandit", "-f", "txt", "-q", tmp_path],
            capture_output=True,
            text=True
        )

        # Geçici dosyayı sil
        os.unlink(tmp_path)

        # Çıktıyı döndür
        return result.stdout if result.stdout else "Kod analizinde sorun yok."

    except Exception as e:
        return f"Hata oluştu: {str(e)}"

