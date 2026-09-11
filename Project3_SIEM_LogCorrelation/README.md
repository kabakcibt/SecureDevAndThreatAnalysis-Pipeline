#Proje 3: UDP/TCP Log Toplama ve Korelasyon Uygulamasi (SIEM)

Bu proje, ag uzerindeki farkli kaynaklardan gelen log toplama, CEF (Common Event Format)
standardına gore ayristirma, MSSQL veritabaninda depolama, esik tabanli korelasyon kurallari ile tehdit tespiti ve bu sureclerin izlenmesi amaciyla gelistirilmis  kurumsal duzeyde moduler bir **SIEM (Security Information and Event Management)** protopidir.

---

## Proje Mimarisi ve Dosya Yapisi

Proje, sorumlulukların net bir sekilde ayrildigi **8 ana Python modulunden** olusmaktadir:

1. **`app.py`**: SOC analistleri icin gelistirilmis, canli log akisini, istatistikleri ve tespit edilen alarmlari gosteren **Streamlit** tabanli gelismis web arayuzu.
2. **`correlation_engine.py`**: Arka planda surekli calisarak loglari tarayan, Brute Force ve yuksek onem seviyeli kritik olaylari esik kurallarina gore analiz edip alarm ureten motor.
3. **`udp_listener.py`**: 514 numaralı port uzerinden UDP tabanli log paketlerini dinleyen ve hata yalitimi (malformed packet handling) ile guclendirilmis ag dinleyicisi.
4. **`tcp_listener.py`**: Belirlenen port uzerinden TCP tabanli baglantilari kabul eden, guvenli akis saglayan log dinleyicisi.
5. **`parsing.py`**: Ham CEF log formatini ayristiran (`parse_cef`) ve veritabanina kayit islemlerini yuruten (`save_to_db`) ana ayristirma motoru.
6. **`db_conn.py`**: MSSQL veritabani baglanti durumunu ve tablo entegrasyonunu dogrulayan bagimsiz test betigi.
7. **`udp_tester.py`**: Test amacli UDP uzerinden normal ve Brute Force (pes pese basarisiz giris) senaryolari simule eden betik.
8. **`tcp_tester.py`**: Test amacli TCP uzerinden yetkisiz erisim ve kritik log senaryolari gonderen betik.

---

## ⚙️ Veritabani Yapisi (`SIEM_DB`)

Projenin arka planinda **Microsoft SQL Server (MSSQL)** kullanmaktadir. Veritabaninda iki temel tablo bulunmaktadir:
* **`Logs`**: Gelen ham loglarin, protokolun, kaynak adresinin ve parse edilmis JSON alanlarinin saklandigi tablo.
* **`Alarms`**: Korelasyon motoru tarafindan tetiklenen guvenlik ihlallerinin (Kural adi, aciklama, kaynak IP ve tarih) kaydedildigi tablo.

---

## 🚀 Kurulum ve Calistirma Adimlari

### 1. Gereksinimler
* Python 3.12
* Microsoft SQL Server & SSMS
* Gerekli Python kutuphaneleri:
  ```bash
  pip install streamlit pyodbc