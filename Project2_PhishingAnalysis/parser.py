import email
from email import policy
import re

def parse_eml_file(file_patch):
    """
    Verilen .eml dosyasini okur, basliklari ve govdeyi ayristirir.
    """
    with open(file_patch, 'rb') as f:
        msg = email.message_from_binary_file(f, policy = policy.default)

    # 1. Temel parser bilgileri
    metadata = {
        "from": msg.get('From', ''),
        "reply-to": msg.get('Reply-To', ''),
        "subject": msg.get("Subject", ''),
        "date": msg.get('Data', '')
    }

    # 2. E-Posta govdesini guvenli cekme
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            # Duz metin (tezt/plain) veya HTML okuma
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text*html"]:
                payload = part.get_payload(decode = True)
                if payload:
                    body += payload.decode('utf-8', errors = 'ignore')

    else:
        payload = msg.get_payload(decode = True)
        if payload:
            body = payload.decode('utf-8', errors = 'ignore')

    # 3. Icerisindeki URL'leri ayiklama (Regex ile)
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

    return {
        "metadata": metadata,
        "body_length": len(body),
        "extracted_urls": list(set(urls)) # Benzersiz URL'ler
    }