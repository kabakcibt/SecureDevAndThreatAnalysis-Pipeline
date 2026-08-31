# Secure Web API & Threat Analysis Pipeline

Bu proje, güvenli web uygulaması geliştirme prensipleri (Secure Coding) dikkate alınarak geliştirilmiş, JWT tabanlı kimlik doğrulama, rol bazlı yetkilendirme (RBAC) ve audit log mekanizmalarına sahip RESTful bir API projesidir.

## Proje Özellikleri
- **Kimlik Doğrulama & Yetkilendirme:** `bcrypt` ile şifreleme ve `JWT` tabanlı oturum yönetimi.
- **Rol Bazlı Erişim (RBAC):** Normal Kullanıcı (User) ve Sistem Yöneticisi (Admin) rolleri için dikey/yatay yetki sınırlandırmaları.
- **Audit Logging:** Yetkisiz erişim denemeleri ve kritik işlemlerin veritabanında (MSSQL) loglanması.
- **Güvenlik Testleri:** Postman üzerinden gerçekleştirilen 401, 403 ve yetki ihlali simülasyonları.

## Kullanılan Teknolojiler
- **Backend:** Python, Flask
- **Veritabanı:** Microsoft SQL Server (MSSQL), pyodbc
- **Güvenlik:** PyJWT, bcrypt
- **Test Araçları:** Postman

## 📂 Proje Yapısı
```text
project1/
│
│── app.py                 # Ana Flask uygulama ve rota dosyaları
│── requirements.txt       # Proje bağımlılıkları
│── README.md              # Proje dokümantasyonu

