from scapy.all import sniff, IP, TCP
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# === Veritabanı Ayarı ===
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ui", "malware_predictions.db"))
engine = create_engine(f"sqlite:///{db_path}")
Base = declarative_base()

class NetworkLog(Base):
    __tablename__ = 'network_logs'
    id = Column(Integer, primary_key=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# === İzlenecek şüpheli portlar ===
SUSPICIOUS_PORTS = [21, 23, 4444]

def log_suspicious_packet(pkt):
    if IP in pkt and TCP in pkt:
        dst_port = pkt[TCP].dport
        if dst_port in SUSPICIOUS_PORTS:
            log = NetworkLog(
                src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                dst_port=dst_port
            )
            session.add(log)
            session.commit()
            print(f"[!] Şüpheli trafik: {pkt[IP].src} → {pkt[IP].dst}:{dst_port}")

def start_monitor():
    print("🔍 Ağ trafiği izleniyor... (Ctrl+C ile çık)")
    sniff(filter="tcp", prn=log_suspicious_packet, store=0)
