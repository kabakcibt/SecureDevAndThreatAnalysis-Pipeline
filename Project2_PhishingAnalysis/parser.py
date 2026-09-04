import email
from email import policy
import re
from urllib.parse import urlparse
import ipaddress

def analyze_headers(msg):
    """
    E-posta basliklarini guvenlik acisindan inceler:
    1. From ve Reply-To uyusmazligini kontrol eder.
    2. SPF / DKIM bulgularini basliklar uzerinden arar.
    """
    from_header = msg.get('From', '')
    reply_to_header = msg.get('Reply-To', '')

    from_email_match = re.search(r'<(.+?)>', from_header)
    reply_email_match = re.search(r'<(.+?)>', reply_to_header)

    clean_from = from_email_match.group(1) if from_email_match else from_header.strip()
    clean_reply_to = reply_email_match.group(1) if reply_email_match else reply_to_header.strip()

    # 1. Uyusmazlik kontrolu
    mismatch_detected = False
    if clean_reply_to and clean_from.lower() != clean_reply_to.lower():
        mismatch_detected = True

    # 2. SPF / DKIM durumlarini headerlardan okuma
    auth_results = msg.get('Authentication-Results', '')

    spf_status = "Unknown"
    dkim_status = "Unknown"

    if "spf=pass" in auth_results.lower():
        spf_status = "Pass"
    elif "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
        spf_status = "Fail"

    if "dkim=pass" in auth_results.lower():
        dkim_status = "Pass"
    elif "dkim=fail" in auth_results.lower():
        dkim_status = "Fail"

    return {
        "from_address": clean_from,
        "reply_to_address": clean_reply_to,
        "reply_to_mismatch": mismatch_detected,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "auth_header_raw": auth_results
    }

def extract_and_analyze_urls(body_text):
    """
    E-posta govdesinden URL'leri ayiklar; domain, sema ve IP tespiti yapar.
    """
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    raw_urls = re.findall(url_pattern, body_text)

    parsed_urls_data = []

    for url in raw_urls:
        if url.startswith('www.'):
            full_url = 'http://' + url
        else:
            full_url = url

        parsed_url = urlparse(full_url)
        domain = parsed_url.netloc

        if ':' in domain:
            domain = domain.split(':')[0]

        is_ip_address = False
        try:
            ipaddress.ip_address(domain)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        parsed_urls_data.append({
            "original_url": url,
            "domain": domain,
            "scheme": parsed_url.scheme,
            "is_ip_address": is_ip_address
        })

    return parsed_urls_data

def parse_eml_file(file_path):
    """
    Verilen .eml dosyasini okur, basliklari ve govdeyi ayristirir.
    """
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy = policy.default)

    # 1. Temel parser bilgileri
    metadata = {
        "from": msg.get('From', ''),
        "reply-to": msg.get('Reply-To', ''),
        "subject": msg.get("Subject", ''),
        "date": msg.get('Date', '')
    }

    # 2. E-Posta govdesini guvenli cekme
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            # Duz metin (text/plain) veya HTML okuma
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                payload = part.get_payload(decode = True)
                if payload:
                    body += payload.decode('utf-8', errors = 'ignore')

    else:
        payload = msg.get_payload(decode = True)
        if payload:
            body = payload.decode('utf-8', errors = 'ignore')

    # 3. Icerisindeki URL'leri ayiklama (Regex ile)
    analyzed_urls = extract_and_analyze_urls(body)

    # 4. Guvenlik ve header analizi fonksiyonu
    security_analysis = analyze_headers(msg)

    return {
        "metadata": metadata,
        "security_analysis": security_analysis,
        "body_length": len(body),
        "extracted_urls": analyzed_urls # Burada düz string listesi yerine fonksiyonun ürettiği analyzed_urls olmalı!
    }