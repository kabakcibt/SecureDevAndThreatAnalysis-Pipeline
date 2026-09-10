import streamlit as st
import pandas as pd
import pyodbc

# Sayfa yapilandirmasi
st.set_page_config(
    page_title = "SIEM Dashboard",
    page_icon = "🛡️",
    layout = "wide"
)

# MSSQL Baglanti bilgileri
DB_CONFIG = (
    "Driver={SQL Server};"
    "Server=localhost\\SQLEXPRESS;"
    "Database=SIEM_DB;"
    "Trusted_Connection=yes;"
)

def get_data(query):
    try:
        conn = pyodbc.connect(DB_CONFIG)
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Veritabani baglanti hatasi: {e}")
        return pd.DataFrame()

# Baslik
st.title("🛡️ SIEM Merkezi Guvenlik Paneli")
st.divider()

# Metrikler
logs_count_df = get_data("SELECT COUNT(*) as Total FROM Logs")
alarms_count_df = get_data("SELECT COUNT(*) as Total FROM Alarms")

total_logs = logs_count_df['Total'].iloc[0] if not logs_count_df.empty else 0
total_alarms = alarms_count_df['Total'].iloc[0] if not alarms_count_df.empty else 0

col1, col2 = st.columns(2)
col1.metric("Toplam Log Sayisi", total_logs)
col2.metric("Uretilen Alarm Sayisi", total_alarms)

st.divider()

# Tablolar
tab1, tab2 = st.tabs(["🚨 Guvenlik Alarmlari", "📃 Canli Log Akisi"])

with tab1:
    st.subheader("Tespit Edilen Tehditler ve Alarmlar")
    
    # Alarm Filtreleme
    search_ip_alarm = st.text_input("Alarm Ara (IP veya Kural Adina Gore):", key="alarm_search")
    
    query_alarms = "SELECT Id, RuleName, Description, SourceIP, CreatedDate FROM Alarms ORDER BY CreatedDate DESC"
    alarms_df = get_data(query_alarms)
    
    if not alarms_df.empty:
        if search_ip_alarm:
            alarms_df = alarms_df[
                alarms_df['SourceIP'].str.contains(search_ip_alarm, case=False, na=False) |
                alarms_df['RuleName'].str.contains(search_ip_alarm, case=False, na=False)
            ]
        st.dataframe(alarms_df, use_container_width=True)
    else:
        st.info("Henuz uretilmis bir guvenlik alarmi bulunmuyor.")

with tab2:
    st.subheader("Veritabanina Kaydedilen Loglar ve Filtreleme")
    
    # Log Filtreleme Alanları (Sidebar veya Ust Menu)
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        proto_filter = st.selectbox("Protokol Filtrele", ["Tumu", "TCP", "UDP"])
    with col_f2:
        search_ip_log = st.text_input("Kaynak IP veya Icerik Ara:", key="log_search")

    query_logs = "SELECT SourceAddress, Protocol, RawLog, LogDate FROM Logs ORDER BY LogDate DESC"
    logs_df = get_data(query_logs)
    
    if not logs_df.empty:
        # Protokol Filtresi Uygulama
        if proto_filter != "Tumu":
            logs_df = logs_df[logs_df['Protocol'] == proto_filter]
            
        # Arama Filtresi Uygulama
        if search_ip_log:
            logs_df = logs_df[
                logs_df['SourceAddress'].str.contains(search_ip_log, case=False, na=False) |
                logs_df['RawLog'].str.contains(search_ip_log, case=False, na=False)
            ]
            
        st.dataframe(logs_df, use_container_width=True)
    else:
        st.info("Veritabaninda kayitli log bulunamadi.")