-- Veritabanını oluştur ve içine geç
CREATE DATABASE SIEM_DB;
GO

USE SIEM_DB;
GO

-- 1. Logların tutulacağı tablo
CREATE TABLE Logs (
ID INT IDENTITY(1,1) PRIMARY KEY,
LogDate DATETIME DEFAULT GETDATE(),
Protocol VARCHAR(10),           -- UDP veya TCP
SourceAddress VARCHAR(50),      -- Paketi gönderen IP:Port
RawLog NVARCHAR(MAX),           -- Ham CEF verisi
ParsedFields NVARCHAR(MAX)      -- Parse edilmiş JSON verisi
);
GO

-- 2. Korelasyon sonucu oluşacak alarmların tablosu
CREATE TABLE Alarms (
ID INT IDENTITY(1,1) PRIMARY KEY,
CreatedDate DATETIME DEFAULT GETDATE(),
RuleName VARCHAR(100),          -- İhlal edilen kural adı
Description NVARCHAR(MAX),      -- Detaylı açıklama
SourceIP VARCHAR(50)            -- İhlali yapan IP
);
GO