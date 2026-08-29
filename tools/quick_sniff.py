"""Quick 10-second live capture test — uses Scapy's default active interface."""
import time
from scapy.config import conf
from pipeline.ingest.live_capture import capture_live, stop_capture

count = 0
def on_pkt(p):
    global count
    count += 1
    print(f"  [{count}] {p.summary()}")

iface = conf.iface  # Scapy's auto-detected default interface
print(f"Capturing on: {iface}  (10 seconds)\n")
capture_live(str(iface), on_packet=on_pkt)
time.sleep(10)
stop_capture()
print(f"\nDone. {count} packets captured.")
