import re
import json
import pyodbc

conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost\\SQLEXPRESS;"
    "DATABASE=SIEM_DB;"
    "Trusted_Connection=yes;"
)

def parse_cef(cef_log):
    """
    CEF formatindaki ham log metnini cozup Python dictionary yapisina donusturur.
    """
    try:
        parts = cef_log.split('|')
        if len(parts) < 8:
            return None
            
        device = {
            "DeviceVendor": parts[1],
            "DeviceProduct": parts[2],
            "DeviceVersion": parts[3],
            "DeviceEventClassID": parts[4],
            "Name": parts[5],
            "Severity": parts[6]
        }
        
        extension_str = "|".join(parts[7:])
        extensions = {}
        pattern = r'(\w+)=([^=]+)(?=\s+\w+=|$)'
        matches = re.findall(pattern, extension_str)
        
        for key, value in matches:
            extensions[key.strip()] = value.strip()
            
        return {**device, **extensions}

    except Exception as e:
        print(f"[-] Log parse hatasi: {e}")
        return None

def save_to_db(raw_log, parsed_data):
    """
    Ham logu ve parse edilmis veriyi SIEM_DB Logs tablosuna kaydeder.
    """
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        sql_query = """
            INSERT INTO Logs (Protocol, SourceAddress, RawLog, ParsedFields)
            VALUES (?, ?, ?, ?)
        """
        
        protocol = parsed_data.get("proto", "UNKNOWN")
        src_ip = parsed_data.get("src", "0.0.0.0")
        src_port = parsed_data.get("spt", "0")
        source_address = f"{src_ip}:{src_port}"
        
        parsed_json_str = json.dumps(parsed_data)
        
        cursor.execute(sql_query, (protocol, source_address, raw_log, parsed_json_str))
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"[-] Veritabani kayit hatasi: {e}")