import scapy.all as scapy
import hashlib
import requests
import time
from threading import Thread, Event

VT_API_KEY = None  # Bunu dışarıdan set edeceksin (örn. app.py’den)

class NetworkAnalyzer:
    def __init__(self, vt_api_key=None):
        self.vt_api_key = vt_api_key
        self.stop_event = Event()
        self.packets_data = []

    def start_sniff(self, packet_count=20, iface=None):
        """
        Paketleri yakalamaya başla, packet_count kadar paket yakaladıktan sonra durur.
        """
        self.packets_data.clear()
        self.stop_event.clear()

        def process_packet(packet):
            # IP paketlerine bak
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                timestamp = time.strftime("%H:%M:%S")

                # Durum belirleme (basit örnek, gerçek kuralları burada koyabilirsin)
                durum = self.evaluate_packet(src, dst, proto)

                self.packets_data.append({
                    "zaman": timestamp,
                    "kaynak": src,
                    "hedef": dst,
                    "protokol": proto,
                    "durum": durum
                })

                if len(self.packets_data) >= packet_count:
                    self.stop_event.set()

        scapy.sniff(prn=process_packet, stop_filter=lambda x: self.stop_event.is_set(), iface=iface)

    def evaluate_packet(self, src_ip, dst_ip, proto):
        """
        Basit anomali ve VT tabanlı kontrol.
        Protokol: 6=TCP, 17=UDP, vs.
        """
        # Burada VirusTotal IP reputasyon kontrolü yapılabilir
        if self.vt_api_key:
            ip_status = self.check_ip_virustotal(src_ip)
            if ip_status == "malicious":
                return "Anomali"
        
        # Basit kural: TCP protokolü güvenli, diğerleri şüpheli (örnek)
        if proto == 6:
            return "Güvenli"
        else:
            return "Şüpheli"

    def check_ip_virustotal(self, ip):
        """
        VirusTotal IP reputasyon sorgusu.
        """
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                # Örnek olarak kötü amaçlı olup olmadığını kontrol et
                malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                if malicious_count > 0:
                    return "malicious"
                else:
                    return "clean"
            else:
                return "unknown"
        except Exception:
            return "error"

def analyze_live_traffic(packet_count=20, iface=None, vt_api_key=None):
    analyzer = NetworkAnalyzer(vt_api_key=vt_api_key)
    analyzer.start_sniff(packet_count=packet_count, iface=iface)
    return analyzer.packets_data

