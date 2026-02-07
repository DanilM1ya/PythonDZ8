#!/usr/bin/env python3
import os
from scapy.all import sniff, wrpcap, rdpcap, Raw

def capture():
    print("Отключаем RST-пакеты ОС...")
    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")
    
    print("\nЗапускаем перехват трафика на порту 8000 (20 секунд)...")
    print("Сразу в другом окне выполняйте:")
    print("  curl 'http://localhost:8000/?q=<script>alert(1)</script>'")
    print("  curl 'http://localhost:8000/?q=<img src=x onerror=alert(2)>'\n")
    
    packets = sniff(filter="tcp port 8000", timeout=20, store=True)
    
    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null")
    
    print(f"\n✅ Перехвачено пакетов: {len(packets)}")
    wrpcap("xss_traffic.pcap", packets)
    print("✅ Файл сохранён: xss_traffic.pcap")
    return packets

def analyze(packets):
    print("\nПоиск XSS в трафике...")
    patterns = ['<script>', 'alert(', 'onerror=']
    found = False
    
    for pkt in packets:
        if pkt.haslayer(Raw):
            try:
                data = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                for pat in patterns:
                    if pat in data:
                        found = True
                        idx = data.find(pat)
                        ctx = data[max(0, idx-30):idx+70]
                        print(f"⚠️  Найдено '{pat}': ...{ctx}...")
            except:
                pass
    
    if found:
        print("\n" + "="*60)
        print("✅ XSS-атака обнаружена в трафике!")
        print("="*60)
    else:
        print("\nℹ️  XSS не найдена")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        pkts = rdpcap("xss_traffic.pcap")
        analyze(pkts)
    else:
        pkts = capture()
        analyze(pkts)
