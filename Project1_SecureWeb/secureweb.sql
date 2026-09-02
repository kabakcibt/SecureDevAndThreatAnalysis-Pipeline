-- 1. Veritabani olusturma
CREATE DATABASE SecureTaskManagerDB;
GO

-- 2. Veritabani icerisine girme
USE SecureTaskManagerDB;
GO

-- 3. Kullanıcı Tablosu
CREATE TABLE Users (
id INT IDENTITY(1,1) PRIMARY KEY,
username VARCHAR(50) NOT NULL UNIQUE,
password_hash VARCHAR(255) NOT NULL,
role VARCHAR(20) NOT NULL DEFAULT 'user',
created_at DATETIME DEFAULT GETDATE()
);

-- 4. Gorevler Tablosu
CREATE TABLE Tasks(
id INT IDENTITY(1,1) PRIMARY KEY,
user_id INT NOT NULL,
title VARCHAR(100) NOT NULL,
description TEXT NULL,
status VARCHAR(20) DEFAULT 'pending',
created_at DATETIME DEFAULT GETDATE()
FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 5. Denetim Gunlukleri (Audit Logs) Tablosu
CREATE TABLE AuditLogs (
id INT IDENTITY(1,1) PRIMARY KEY,
username VARCHAR(50) NULL,
action VARCHAR(50) NOT NULL,
ip_address VARCHAR(50) NULL,
details TEXT NULL,
created_at DATETIME DEFAULT GETDATE()
);