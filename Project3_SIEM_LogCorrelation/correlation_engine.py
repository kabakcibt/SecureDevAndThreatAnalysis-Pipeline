import pyodbc
import time
from datetime import datetime, timedelta

#MSSQL Baglanti Bilgileri
DB_CONFİG = (
    "Driver={SQL Server};"
    "Server=localhost\\SQLEXPRESS;"
    "Database=SIEM_DB;"
    "Trusted_Connection=yes;"
)

def get_db_connection():
    try:
        return pyodbc.connect(DB_CONFİG)
    except Exception as e:
        print(f"[-] Veritabani baglanti hatasi: {e}")
        return None

def check_rules():
    conn = get_db_connection()
    if not conn:
        return

    cursor = conn.cursor()

    # Zaman Filtresi: Son 5 Dakika
    five_minutes_ago = datetime.now() - timedelta(minutes=5)
    one_minute_ago = datetime.now() -timedelta(minutes=1)

    query = """
        SELECT SourceAddress, RawLog, LogDate 
        FROM Logs 
        WHERE LogDate >= ?
    """

    cursor.execute(query, (five_minutes_ago,))
    rows = cursor.fetchall()

    failed_attempts = {}

    for row in rows:
        raw_ip = row.SourceAddress if row.SourceAddress else "127.0.0.1"
        clean_ip = raw_ip.split(':')[0].strip()

        raw_log = str(row.RawLog) if row.RawLog else ""
        raw_log_lower = raw_log.lower()

        # Kural 1: Son 5 dakika da 10 ve üzeri başarısız giriş (Brute Force)
        if 'failed login' in raw_log_lower or "outcome=failure" in raw_log_lower or "failed" in raw_log_lower or "4625" in raw_log_lower:
            if row.LogDate >= five_minutes_ago:
                failed_attempts[clean_ip] = failed_attempts.get(clean_ip, 0) + 1

        # Kural 2: CEF Logu ve Kritik Olay Tespiti
        if "critical" in raw_log_lower or "severity=7" in raw_log_lower or "severity=8" in raw_log_lower or "severity=9" in raw_log_lower or "severity=10" in raw_log_lower:
            rule2_name = "High Severity / Critical CEF Log Detected"
            rule2_desc = f"Kritik onem seviyesinde log tespit edildi: {raw_log[:60]}"
            
            cursor.execute("""
                SELECT COUNT(*) FROM Alarms 
                WHERE RuleName = ? AND SourceIP = ? AND CreatedDate >= ?
            """, (rule2_name, clean_ip, one_minute_ago))
            
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO Alarms (RuleName, Description, SourceIP, CreatedDate)
                    VALUES (?, ?, ?, GETDATE())
                """, (rule2_name, rule2_desc, clean_ip))
                conn.commit()
                print(f"\n[!] ALARM: {clean_ip} kaynakli yuksek riskli log yakalandi!")

    for ip, count in failed_attempts.items():
        if count >= 10:
            rule1_name = "Brute Force Attack Detected (Threshold: 10/5m)"
            rule1_desc = f"Son 5 dakika icinde {ip} adresinden {count} adet basarisiz islem tespit edildi."

            cursor.execute("""
                SELECT COUNT(*) FROM Alarms 
                WHERE SourceIP = ? AND RuleName = ? AND CreatedDate >= ?
            """, (ip, rule1_name, five_minutes_ago))

            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO Alarms (RuleName, Description, SourceIP, CreatedDate)
                """, (rule1_name, rule1_desc, ip))
                conn.commit()
                print(f"\n[!] ALARM: {ip} -> Son 5 dakikada {count} Basarisiz Giris!")

    conn.close()

def run_engine():
    print("[+] Korelasyon Motoru baslatildi. Kurallar taraniyor...")
    while True:
        try:
            check_rules()
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[-] Motor durduruldu.")
            break
        except Exception as e:
            print(f"[-] Hata: {e}")
            time.sleep(3)

if __name__ == "__main__":
    run_engine()