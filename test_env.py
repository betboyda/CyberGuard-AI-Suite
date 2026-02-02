import os
from dotenv import load_dotenv

load_dotenv()  # varsayılan olarak şu an çalıştırılan klasörde .env dosyasını arar

print("Çalışma dizini:", os.getcwd())
print("VT_API_KEY:", os.getenv("VT_API_KEY"))
