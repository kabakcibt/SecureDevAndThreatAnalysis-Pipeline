import email
from email import policy
import re
from urllib.parse import urlparse
import ipaddress
import hashlib

def analyze_headers(msg):
    """
    E-posta basliklarini guvenlik acisindan inceler:
    1. From ve Reply-To uyusmazligini kontrol eder.
    2. SPF, DKIM ve DMARC bulgularini basliklar uzerinden arar.
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

    # 2. SPF / DKIM / DMARC durumlarini headerlardan okuma
    auth_results = msg.get('Authentication-Results', '')

    spf_status = "Unknown"
    dkim_status = "Unknown"
    dmarc_status = "Unknown"

    if "spf=pass" in auth_results.lower():
        spf_status = "Pass"
    elif "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
        spf_status = "Fail"

    if "dkim=pass" in auth_results.lower():
        dkim_status = "Pass"
    elif "dkim=fail" in auth_results.lower():
        dkim_status = "Fail"

    if "dmarc=pass" in auth_results.lower():
        dmarc_status = "Pass"
    elif "dmarc=fail" in auth_results.lower() or "dmarc=permerror" in auth_results.lower() or "dmarc=temperror" in auth_results.lower():
        dmarc_status = "Fail"

    return {
        "from_address": clean_from,
        "reply_to_address": clean_reply_to,
        "reply_to_mismatch": mismatch_detected,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "auth_header_raw": auth_results
    }

def extract_and_analyze_attachments(msg):
    """
    E-posta icindeki ekleri guvenli bir sekilde tarar.
    dosyalari calistirmadan statik analiz yapar; boyut, MIME tipi ve hash (MD5 / SHA256) uretir.
    """
    attachments_data = []

    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")

        if "attachment" in content_disposition.lower() or part.get_filename():
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode = True)
                if payload:
                     file_size = len(payload)
                     mime_type = part.get_content_type()

                     md5_hash = hashlib.md5(payload).hexdigest()
                     sha256_hash = hashlib.sha256(payload).hexdigest()

                     attachments_data.append({
                         "filename": filename,
                         "size_bytes": file_size,
                         "mime_type": mime_type,
                         "md5": md5_hash,
                         "sha256": sha256_hash
                     })

    return attachments_data

def calculate_risk_score(security_analysis, urls, attachments):
    """
    Parser verilerini analiz ederek e-postanin risk puanini ve seviyesini hesaplar.
    """
    score = 0
    reasons = []

    # 1. Header Guvenlik Kontrolleri
    if security_analysis.get("reply_to_mismatch"):
        score += 20
        reasons.append("Reply-To ve From adresleri uyusmuyor (+ 20p)")

    if security_analysis.get("spf_status") == "Fail":
        score += 15
        reasons.append("SPF dogrulamasi basarisiz (+ 15p)")

    if security_analysis.get("dkim_status") == "Fail":
        score += 15
        reasons.append("DKIM imzasi basarisiz (+ 15p)")

    if security_analysis.get("dmarc_status") == "Fail":
        score += 15
        reasons.append("DMARC dogrulamasi basarisiz (+ 15p)")

    # 2. URL ve Domain Kontrolleri
    for url in urls:
        if url.get("is_ip_address"):
            score += 20
            reasons.append(f"Supheli URL icinde dogrudan IP adresi tespit edildi: {url['domain']} (+ 20p)")

    if len(urls) > 1:
        score += 10
        reasons.append(f"E-posta icinde coklu URL tespiti (Toplam: {len(urls)}) (+ 10p)")

    # 3. Ek dosya (attachments) kontrolleri
    if attachments:
        score += 15
        reasons.append("E-postada ek dosya (attachment) tespit edildi (+ 15p)")

        dangerous_extensions = ('.exe', '.bat', '.scr', '.pif', '.cmd', '.vbs', '.js', '.ps1')
        for att in attachments:
            filename_lower = att['filename'].lower()
            if filename_lower.endswith(dangerous_extensions):
                score += 25
                reasons.append(f"KRITIK: Supheli/zararli uzantili ek dosya tespit edildi: {att['filename']} (+ 25p)")

    # 4. Risk seviyesi siniflandirmasi
    if score >= 60:
        risk_level = "Yuksek Risk (Kritik Phishing Tehdidi)"
    elif score >= 30:
        risk_level = "Orta Risk (Supheli Aktivite)"
    elif score > 0:
        risk_level = "Dusuk Risk (Hafif Supheli)"
    else:
        risk_level = "Temiz (Risk Yok)"

    return {
        "total_score": score,
        "risk_level": risk_level,
        "risk_factors": reasons
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

    metadata = {
        "from": msg.get('From', ''),
        "reply-to": msg.get('Reply-To', ''),
        "subject": msg.get("Subject", ''),
        "date": msg.get('Date', '')
    }

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                payload = part.get_payload(decode = True)
                if payload:
                    body += payload.decode('utf-8', errors = 'ignore')

    else:
        payload = msg.get_payload(decode = True)
        if payload:
            body = payload.decode('utf-8', errors = 'ignore')

    analyzed_urls = extract_and_analyze_urls(body)
    security_analysis = analyze_headers(msg)
    analyzed_attachments = extract_and_analyze_attachments(msg)
    risk_assessment = calculate_risk_score(security_analysis, analyzed_urls, analyzed_attachments)

    return {
        "metadata": metadata,
        "security_analysis": security_analysis,
        "risk_assessment": risk_assessment,
        "body_length": len(body),
        "extracted_urls": analyzed_urls,
        "extracted_attachments": analyzed_attachments
    }