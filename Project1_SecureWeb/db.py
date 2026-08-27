import pyodbc

def get_db_connection():
    server = 'localhost\\SQLEXPRESS'  
    database = 'SecureTaskManagerDB'

    connection_string = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"Trusted_Connection=yes;"
    )

    try:
        conn = pyodbc.connect(connection_string)
        return conn
    except Exception as e:
        print(f"Veritabani baglanti hatasi: {e}")
        return None

if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        print("Tebrikler ! MSSQL veritabani baglantisi basariyla saglandi.")
        conn.close()
    else:
        print("Baglanti kurulamadi!")