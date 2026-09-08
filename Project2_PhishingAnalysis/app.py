import streamlit as st
import os
import json
from parser import parse_eml_file # Parser kodunu sisteme cekiyoruz

# Sayfa yapilandirmasi
st.set_page_config(
    page_title = "Phishing Analiz ve Tehdit Paneli",
    page_icon = "🛡️",
    layout = "wide"
)

st.title("🛡️ Phishing E-posta Analiz ve Risk Puanlama Paneli")
st.markdown("Bu panel, supheli '.eml' dosyalarini guvenli bir sekilde analiz ederek baslik uyumsuzluklarini, tehlikeli linkleri ve ek dosyalari inceler.")

# File Uploader
uploaded_file = st.file_uploader("Analiz edilecek .eml uzantili e-postayi yukleyin", type=["eml"])

if uploaded_file is not None:
    temp_file_path = "temp_email.eml"
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success("E-posta basariyla yuklendi! Analiz gerceklestiriliyor...")

    # Parser Motorunun calistirilmasi
    parsed_result = parse_eml_file(temp_file_path)

    # Analizi biten yuklenen dosyayi temizleme
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

    # Sonuclari Ekrana Yansitma
    st.divider()

    # 1. Metrikler ve Genel Bakis
    risk_info = parsed_result.get("risk_assessment", {})
    metadata = parsed_result.get("metadata", {})
    sec_analysis = parsed_result.get("security_analysis", {})

    with st.container(border=True):
        st.subheader("📊 Genel Tehdit Özeti")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label = "Toplam Risk Puani", value = f"{risk_info.get('total_score', 0)} / 100")
        with col2:
            st.metric(label = "Risk Seviyesi", value = risk_info.get('risk_level', 'Bilinmiyor'))
        with col3:
            st.metric(label = "Bulunan URL Sayisi", value = len(parsed_result.get('extracted_urls', [])))

    # 2. E-posta Meta Verileri ve Güvenlik Durumu
    with st.container(border=True):
        st.subheader("📧 E-Posta Meta Verileri ve Güvenlik Doğrulamaları")
        st.write(f"**Gonderen (From):** `{metadata.get('from')}`")
        st.write(f"**Yanitla (Reply-To):** `{metadata.get('reply-to')}`")
        st.write(f"**Konu (Subject):** {metadata.get('subject')}")
        st.write(f"**Tarih (Date):** {metadata.get('date')}")
        st.divider()
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.write(f"**SPF Durumu:** {sec_analysis.get('spf_status')}")
        with col_b:
            st.write(f"**DKIM Durumu:** {sec_analysis.get('dkim_status')}")
        with col_c:
            st.write(f"**DMARC Durumu:** {sec_analysis.get('dmarc_status')}")

    # 3. Risk Faktorleri
    with st.container(border=True):
        st.subheader("☠️ Tespit Edilen Tehdit / Risk Faktorleri")
        factors = risk_info.get('risk_factors', [])
        if factors:
            for factor in factors:
                st.warning(factor)
        else:
            st.success("Hicbir risk faktoru tespit edilmedi, e-posta guvenli gorunuyor.")

    # 4. URL Analiz Sonuclari
    with st.container(border=True):
        st.subheader("🌐 İncelenen URL ve Domainler")
        urls = parsed_result.get('extracted_urls', [])
        if urls:
            for u in urls:
                with st.expander(f"Link: {u['original_url']}"):
                    st.write(f"**Domain:** {u['domain']}")
                    st.write(f"**Sema (Scheme):** {u['scheme']}")
                    st.write(f"**IP Adresi mi?:** {'Evet ⚠️' if u['is_ip_address'] else 'Hayir ✅'}")
        else:
            st.info("E-posta govdesinde herhangi bir URL bulunamadi.")

    # 5. Ek Dosya (Attachment) Analiz Sonuclari
    with st.container(border=True):
        st.subheader("🔗 Ek Dosya (Attachment) Guvenlik Raporu")
        attachments = parsed_result.get('extracted_attachments', [])
        if attachments:
            for att in attachments:
                with st.expander(f"Dosya: {att['filename']} ({att['size_bytes']} bytes)"):
                    st.write(f"**MIME Tipi:** {att['mime_type']}")
                    st.code(f"MD5 Hash    : {att['md5']}", language="text")
                    st.code(f"SHA256 Hash : {att['sha256']}", language="text")
        else:
            st.success("E-postada ek dosya (attachment) bulunmuyor.")

    # 6. IOC ve Analiz Raporunu JSON Olarak İndirme (Dışa Aktarma)
    st.divider()
    json_data = json.dumps(parsed_result, indent=4, ensure_ascii=False)
    st.download_button(
        label="📥 Analiz Raporunu ve IOC'leri JSON Olarak İndir",
        data=json_data,
        file_name="phishing_analysis_report.json",
        mime="application/json"
    )

else:
    st.info("Lutfen baslamak icin yukaridaki alana bir '.eml' dosyasi yukleyin.")