import sqlite3

conn = sqlite3.connect("storage/app.db")
for row in conn.execute("SELECT alert_id, threat_class, severity, confidence, src_ip, dst_ip FROM alerts"):
    print(row)
conn.close()
