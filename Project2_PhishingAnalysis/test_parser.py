from parser import parse_eml_file

# Olusturdugumuz test eml dosyasinin yolunu veriyoruz
dosya_yolu = "ornek.eml"

print("*** E-posta analizi baslatiliyor...")
sonuc = parse_eml_file(dosya_yolu)

# Sonuclari ekrana yazdirma
print("\n--- PARSER TEST SONUÇLARI ---")

print(f"Gonderen (From): {sonuc['metadata']['from']}")
print(f"Yanitla (Reply-To): {sonuc['metadata']['reply-to']}")
print(f"Konu (Subject): {sonuc['metadata']['subject']}")
print(f"Tarih (Date): {sonuc['metadata']['date']}")

print("\n--- GUVENLIK ANALIZI (Header Check) ---")

sec = sonuc['security_analysis']
print(f"Temizlenmis From: {sec['from_address']}")
print(f"Temizlenmis Reply-To: {sec['reply_to_address']}")
print(f"Reply-To uyusmazligi var mi?: {sec['reply_to_mismatch']}")
print(f"SPF Durumu: {sec['spf_status']}")
print(f"DKIM Durumu: {sec['dkim_status']}")

print(f"\n--- AYIKLANAN URL'LER ({len(sonuc['extracted_urls'])} adet) ---")
for url in sonuc['extracted_urls']:
    print(f" -> {url}")
print("-----------------------------------")