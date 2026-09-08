# Phishing Email Analysis and Risk Scoring Pipeline (Project 2)

Bu proje, SOC (Guvenlik Operasyon Merkezi) analistlerinin supheli e-postalari hizli, guvenli ve aciklanabilir bir sekilde incelemesi amaciyla gelistirilmis kural tabanli bir Phishing Analiz ve Risk Puanlama aracidir.

## 🗂️ Temel Ozellikler
- **EML & Metin Ayristirma:** Ham e-posta dosyalarindan basliklari, govdeyi ve ekleri ayirir.
- **Guvenlik Dogrulamalari:** SPF, DKIM ve DMARC baslik durumlarini kontrol eder.
- **Header Uyuşmazlik Tespiti:** `From` ve `Reply-to` alanlari arasindaki tutarsizliklari yakalar.
- **URL & Domain Analizi:** Govdedeki linkleri ayiklar, sema analizi yapar ve dogrudan IP adresi kullanimini tespit eder.
- **Guvenli Statik Ek Dosya Analizi:** Ek dosyalari asla calistirmadan (sandbox/execution yok) boyut, MIME tipi ve kriptografik parmak izlerini (**MD5 & SHA256**) hesaplar.
- **Aciklanabilir Risk Puanlama:** Tespit edilen her anomaliye gore 0-100 arasi agirlikli bir skor ve risk seviyesi uretir.
- **Arayuz & Disa Aktarma:** Streamlit tabanli kart yapili arayuz sunar ve raporlarin **JSON** formatinda disa aktarilmasina olanak tanir.

## 🛠️ Kurulum ve Calistirma

1. Gerekli kutuphaneyi yukleyin:
   ```bash
   pip install -r requirements.txt

2. Proje klasorune girin:
   ```bash
   cd Project2_PhishinAnalysis

3. Arayuzu baslatin:
   ```bash
   streamlit run app.py