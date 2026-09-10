import pyodbc

conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost\\SQLEXPRESS;"
    "DATABASE=SIEM_DB;"
    "Trusted_Connection=yes;"
)

def test_connection():
    try:
        conn = pyodbc.connect(conn_str)
        print("[+] MSSQL Veritabani baglantisi basarili.")
        
        cursor = conn.cursor()
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES")
        tables = cursor.fetchall()
        
        print("Veritabanindaki Tablolar:")
        for table in tables:
            print(f" - {table[0]}")
            
        conn.close()
    except Exception as e:
        print("[-] Baglanti Hatasi:", e)

if __name__ == "__main__":
    test_connection()