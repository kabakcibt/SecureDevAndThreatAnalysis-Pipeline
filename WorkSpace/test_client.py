import requests

# Sunucumuzun adresi
url = 'http://127.0.0.1:5000/api/items'

# Sunucuya gonderecegimiz yeni guvenlik logu verisi
new_data = {
    "name": "Supheli IP Baglanti Girisimi",
    "status": "Inceleniyor"
}

# Sunucuya POST(veri ekleme) istegi atiyoruz
cevap = requests.post(url, json = new_data)

print(f"Sunucudan donen HTTP Durum Kodu: {cevap.status_code}")
print(f"Sunucunun cevabi: {cevap.json()}")

